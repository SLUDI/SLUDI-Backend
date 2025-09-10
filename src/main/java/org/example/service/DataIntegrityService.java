package org.example.service;

import io.ipfs.multibase.Base58;
import org.example.entity.*;
import org.example.integration.IPFSIntegration;
import org.example.repository.IPFSContentRepository;
import org.example.security.CryptographyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.logging.Logger;

@Service
public class DataIntegrityService {

    private static final Logger LOGGER = Logger.getLogger(DataIntegrityService.class.getName());

    @Autowired
    private HyperledgerService hyperledgerService;

    @Autowired
    private CryptographyService cryptographyService;

    @Autowired
    private IPFSContentRepository ipfsContentRepository;

    @Autowired
    private IPFSIntegration ipfsIntegration;

    public boolean verifyIPFSIntegrity(String userId, BiometricHashes biometricHashes) {
        // Get PostgreSQL records for this user
        List<IPFSContent> ipfsContentList = ipfsContentRepository.findByOwnerUserId(UUID.fromString(userId));

        if (ipfsContentList.isEmpty()) {
            LOGGER.warning("No IPFS records found for user: " + userId);
            return false;
        }

        // Verify each biometric type
        boolean fingerprintOk = verifySingleBiometric(ipfsContentList, "fingerprint", biometricHashes.getFingerprintHash());
        boolean faceOk       = verifySingleBiometric(ipfsContentList, "face", biometricHashes.getFaceImageHash());

        return fingerprintOk && faceOk;
    }

    private boolean verifySingleBiometric(List<IPFSContent> ipfsContentList, String subcategory, String blockchainHash) {
        // matching IPFSContent from DB
        IPFSContent content = ipfsContentList.stream()
                .filter(c -> subcategory.equalsIgnoreCase(c.getSubcategory()))
                .findFirst()
                .orElse(null);

        if (content == null) {
            LOGGER.warning("No IPFS content found for subcategory: " + subcategory);
            return false;
        }

        // Compare DB vs Blockchain
        if (!Objects.equals(content.getIpfsHash(), blockchainHash)) {
            LOGGER.warning("DB hash != Blockchain hash for " + subcategory);
            return false;
        }

        // Fetch file from IPFS and recompute hash
        byte[] fileData = ipfsIntegration.retrieveFile(blockchainHash);
        String computedHash = computeIpfsHash(fileData);

        if (!Objects.equals(computedHash, blockchainHash)) {
            LOGGER.warning("IPFS file hash != Blockchain hash for " + subcategory);
            return false;
        }

        return true;
    }


    private boolean compareAuthentication(List<String> authentication, List<String> authentication1) {
        if (authentication == null) return authentication1 == null;
        if (authentication1 == null || authentication.size() != authentication1.size()) return false;

        for (String auth : authentication) {
            boolean match = authentication1.contains(auth);
            if (!match) return false;
        }
        return true;
    }

    private boolean compareContext(List<String> context, List<String> context1) {
        if (context == null) return context1 == null;
        if (context1 == null || context.size() != context1.size()) return false;

        for (String ctx : context) {
            boolean match = context1.contains(ctx);
            if (!match) return false;
        }
        return true;
    }

    private boolean compareCredentialTypes(List<String> credentialTypes, List<String> credentialTypes1) {
        if (credentialTypes == null) return credentialTypes1 == null;
        if (credentialTypes1 == null || credentialTypes.size() != credentialTypes1.size()) return false;

        for (String type : credentialTypes) {
            boolean match = credentialTypes1.contains(type);
            if (!match) return false;
        }
        return true;
    }

    private String computeIpfsHash(byte[] fileData) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] sha256 = digest.digest(fileData);

            // Prepend multihash prefix for IPFS
            byte[] multihash = new byte[sha256.length + 2];
            multihash[0] = 0x12; // SHA2
            multihash[1] = 0x20; // length 32
            System.arraycopy(sha256, 0, multihash, 2, sha256.length);

            return Base58.encode(multihash); // same encoding IPFS uses
        } catch (Exception e) {
            throw new RuntimeException("Error computing IPFS hash", e);
        }
    }



}
