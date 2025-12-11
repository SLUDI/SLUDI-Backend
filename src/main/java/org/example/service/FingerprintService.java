package org.example.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.machinezoo.sourceafis.FingerprintImage;
import com.machinezoo.sourceafis.FingerprintMatcher;
import com.machinezoo.sourceafis.FingerprintTemplate;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.FingerprintVerificationRequest;
import org.example.dto.FingerprintVerificationResult;
import org.example.entity.CitizenUser;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.example.integration.IPFSIntegration;
import org.example.repository.CitizenUserRepository;
import org.example.utils.HashUtil;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.List;

import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
public class FingerprintService {
    private final CitizenUserRepository citizenUserRepository;
    private final IPFSIntegration ipfsIntegration;

    //private long dbHandle = 0;

    @org.springframework.beans.factory.annotation.Autowired
    private CitizenUserRepository appUserRepository;

    public FingerprintService(CitizenUserRepository citizenUserRepository, IPFSIntegration ipfsIntegration) {
        this.citizenUserRepository = citizenUserRepository;
        this.ipfsIntegration = ipfsIntegration;
    }

//    @PostConstruct
//    public void init() {
//        // Initialize the SDK (Sensor)
//        int ret = FingerprintSensorEx.Init();
//        if (ret == 0) {
//            System.out.println("ZKFinger SDK Initialized successfully.");
//        } else {
//            System.err.println("ZKFinger SDK Init failed (No sensor connected?). Error code: " + ret);
//        }
//
//        // Initialize the DB (Algorithm)
//        dbHandle = FingerprintSensorEx.DBInit();
//        if (dbHandle != 0) {
//            System.out.println("ZKFinger DB Initialized successfully. Handle: " + dbHandle);
//        } else {
//            System.err.println("Failed to initialize ZKFinger DB. Matching will not work.");
//        }
//    }

//    @PreDestroy
//    public void cleanup() {
//        if (dbHandle != 0) {
//            FingerprintSensorEx.DBFree(dbHandle);
//            dbHandle = 0;
//        }
//        FingerprintSensorEx.Terminate();
//        System.out.println("ZKFinger SDK Terminated.");
//    }
//
//    @Transactional
//    public void registerUser(String username, java.util.List<String> images) {
//        if (appUserRepository.findByUsername(username).isPresent()) {
//            throw new RuntimeException("User already exists: " + username);
//        }
//
//        com.sluid.fingerprint.entity.AppUser user = new com.sluid.fingerprint.entity.AppUser();
//        user.setUsername(username);
//
//        java.util.List<com.sluid.fingerprint.entity.FingerprintData> fpList = new java.util.ArrayList<>();
//        for (String img : images) {
//            com.sluid.fingerprint.entity.FingerprintData fp = new com.sluid.fingerprint.entity.FingerprintData();
//            fp.setImageData(img);
//            fp.setUser(user);
//            fpList.add(fp);
//        }
//        user.setFingerprints(fpList);
//
//        appUserRepository.save(user);
//    }

    @Transactional(readOnly = true)
    public FingerprintVerificationResult verifyUser(FingerprintVerificationRequest request) throws Exception {
        // Fetch citizen
        CitizenUser citizen = citizenUserRepository.findByAnyHash(null, null, HashUtil.sha256(request.getCitizenId()));
        if (citizen == null) {
            throw new Exception("Cannot find user!");
        }

        // Get IPFS hash
        String ipfsHash = citizen.getFingerprintIpfsHash();
        if (ipfsHash == null || ipfsHash.isEmpty()) {
            throw new Exception("No fingerprint embedding found for this citizen");
        }

        // Retrieve biometric data (JSON string containing array of fingerprints)
        String fingerprintsJsonBase64 = ipfsIntegration.retrieveBiometricDataAsString(
                ipfsHash,
                citizen.getId().toString()
        );

        fingerprintsJsonBase64 = fingerprintsJsonBase64.trim().replaceAll("\\s+", "");

        // Parse JSON to get list of fingerprints
        List<String> storedFingerprints = parseJsonToList(fingerprintsJsonBase64);

        if (storedFingerprints == null || storedFingerprints.isEmpty()) {
            throw new Exception("No valid fingerprint data found");
        }

        // Get the probe fingerprint image from request
        String probeFingerprintBase64 = request.getFingerprint();
        if (probeFingerprintBase64 == null || probeFingerprintBase64.isEmpty()) {
            throw new Exception("Probe fingerprint is required");
        }

        // Compare probe against all stored fingerprints
        double maxScore = 0;
        int matchedIndex = -1;

        for (int i = 0; i < storedFingerprints.size(); i++) {
            String storedFingerprintBase64 = storedFingerprints.get(i);
            double score = matchImage(storedFingerprintBase64, probeFingerprintBase64);

            if (score > maxScore) {
                maxScore = score;
                matchedIndex = i;
            }
        }

        // Threshold check (40 for SourceAFIS)
        boolean verified = maxScore > 40;

        String message = verified
                ? "Matched with fingerprint #" + (matchedIndex + 1) + " (Score: " + maxScore + ")"
                : "No match found (Max Score: " + maxScore + ")";

        return new FingerprintVerificationResult(verified, maxScore, message);
    }

    private List<String> parseJsonToList(String jsonString) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            return mapper.readValue(jsonString, new TypeReference<List<String>>() {});
        } catch (JsonProcessingException e) {
            log.error("Failed to parse fingerprints JSON: {}", e.getMessage());
            throw new SludiException(
                    ErrorCodes.JSON_PARSING_FAILED,
                    "Failed to parse stored fingerprints",
                    e
            );
        }
    }


    // Server-side matching using SourceAFIS (Hardware Free)
    public double matchImage(String image1Base64, String image2Base64) {
        if (image1Base64 == null || image2Base64 == null || image1Base64.isEmpty() || image2Base64.isEmpty()) {
            System.err.println("Error: Invalid input images (null or empty)");
            return -1;
        }
        try {
            // Decode Base64
            byte[] img1Raw = Base64.getDecoder().decode(image1Base64);
            byte[] img2Raw = Base64.getDecoder().decode(image2Base64);

            int size = img1Raw.length;

            // Determine dimensions
            int width = 0;
            int height = 0;

            if (size == 147456) {
                width = 512;
                height = 288;
            } else if (size == 112500) {
                // ZK 300x375 (Or 375x300) - Usually Portrait
                width = 300;
                height = 375;
            } else if (size == 92160) {
                width = 256;
                height = 360;
            } else {
                // Fallback / Guess using SQRT or standard ratio
                // Try to find if it fits standard widths
                if (size % 300 == 0) {
                    width = 300;
                    height = size / 300;
                } else if (size % 256 == 0) {
                    width = 256;
                    height = size / 256;
                } else {
                    System.err.println("Unknown Image Resolution for size: " + size);
                    return -1;
                }
            }

            // 1. Prepare Base Images
            // byte[] img1Inverted = invertImage(img1Raw);
            // byte[] img2Inverted = invertImage(img2Raw);

            // // Enhanced (Blur + Contrast)
            // byte[] img1Blurred = medianBlur(img1Raw, width, height);
            // byte[] img2Blurred = medianBlur(img2Raw, width, height);

            // byte[] img1Enhanced = enhanceContrast(img1Blurred, "Finger1");
            // byte[] img2Enhanced = enhanceContrast(img2Blurred, "Finger2");

            // byte[] img1EnhInv = invertImage(img1Enhanced);
            // byte[] img2EnhInv = invertImage(img2Enhanced);

            // SourceAFIS 3.x API:
            double globalMaxScore = 0;
            int bestDpi = 0;
            String winningStrategy = "Unknown";

            // Sweep DPI (Optimized Range: 350-500)
            // Based on empirical data, matches are found here. Saves processing time.
            int[] testDpis = { 350, 400, 450, 500 };

            for (int dpi : testDpis) {
                double s1 = matchPair(img1Raw, img2Raw, dpi, width, height);
                double currentMax = s1;

                if (currentMax > globalMaxScore) {
                    globalMaxScore = currentMax;
                    bestDpi = dpi;
                }
            }

            System.out.println(
                    "FINAL RESULT >>> Score: " + globalMaxScore + " @ DPI: " + bestDpi);
            return globalMaxScore;
        } catch (Exception e) {
            System.err.println("SourceAFIS Match Error: " + e.getMessage());
            e.printStackTrace();
            return -1;
        }
    }

    private double matchPair(byte[] img1, byte[] img2, int dpi, int width, int height) {
        FingerprintImage fpImage1 = new FingerprintImage()
                .dpi(dpi)
                .grayscale(width, height, img1);
        FingerprintTemplate template1 = new FingerprintTemplate(
                fpImage1);

        FingerprintImage fpImage2 = new FingerprintImage()
                .dpi(dpi)
                .grayscale(width, height, img2);
        FingerprintTemplate template2 = new FingerprintTemplate(
                fpImage2);

        FingerprintMatcher matcher = new FingerprintMatcher()
                .index(template1);

        return matcher.match(template2);
    }
}