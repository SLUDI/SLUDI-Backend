package org.example.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.*;
import org.example.entity.*;
import org.example.enums.CredentialsType;
import org.example.enums.ProofPurpose;
import org.example.enums.UserStatus;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.example.integration.IPFSIntegration;
import org.example.repository.CitizenUserRepository;
import org.example.repository.IPFSContentRepository;
import org.example.repository.OrganizationUserRepository;
import org.example.repository.VerifiableCredentialRepository;
import org.example.security.CryptographyService;
import org.example.utils.CredentialClaimsMapper;
import org.example.utils.HashUtil;
import org.example.utils.LicenseNumberGenerator;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@Transactional
public class VerifiableCredentialService {

    private final HyperledgerService hyperledgerService;
    private final CryptographyService cryptographyService;
    private final DigitalSignatureService digitalSignatureService;
    private final IPFSIntegration ipfsIntegration;
    private final CredentialClaimsMapper claimsMapper;
    private final LicenseNumberGenerator licenseNumberGenerator;
    private final OrganizationUserService organizationUserService;
    private final OrganizationUserRepository organizationUserRepository;
    private final VerifiableCredentialRepository verifiableCredentialRepository;
    private final CitizenUserRepository userRepository;
    private final IPFSContentRepository ipfsContentRepository;

    private final ObjectMapper objectMapper = new ObjectMapper();

    public VerifiableCredentialService(
            HyperledgerService hyperledgerService,
            CryptographyService cryptographyService,
            DigitalSignatureService digitalSignatureService,
            IPFSIntegration ipfsIntegration,
            LicenseNumberGenerator licenseNumberGenerator,
            VerifiableCredentialRepository verifiableCredentialRepository,
            CitizenUserRepository userRepository,
            IPFSContentRepository ipfsContentRepository,
            CredentialClaimsMapper claimsMapper,
            OrganizationUserService organizationUserService,
            OrganizationUserRepository organizationUserRepository
    ) {
        this.hyperledgerService = hyperledgerService;
        this.cryptographyService = cryptographyService;
        this.digitalSignatureService = digitalSignatureService;
        this.ipfsIntegration = ipfsIntegration;
        this.licenseNumberGenerator = licenseNumberGenerator;
        this.verifiableCredentialRepository = verifiableCredentialRepository;
        this.userRepository = userRepository;
        this.ipfsContentRepository = ipfsContentRepository;
        this.claimsMapper = claimsMapper;
        this.organizationUserService = organizationUserService;
        this.organizationUserRepository = organizationUserRepository;
    }

    public VCIssuedResponseDto issueIdentityVC(IssueVCRequestDto request, String userName) {
        log.info("Issuing identity VC for DID: {}, CredentialType: {}", request.getDid(), request.getCredentialType());

        try {
            // Find user
            OrganizationUser adminUser = organizationUserRepository.findByUsername(userName)
                    .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

            // Check if user has permission to issue DID
            if (!organizationUserService.verifyUserPermission(userName, "citizen:issue_identity_credentials")) {
                log.warn("User {} attempted to issue DID without permission", userName);
                throw new SludiException(ErrorCodes.INSUFFICIENT_PERMISSIONS);
            }

            // Verify user is active
            if (adminUser.getStatus() != UserStatus.ACTIVE) {
                log.warn("Inactive user {} attempted to issue DID", userName);
                throw new SludiException(ErrorCodes.USER_INACTIVE);
            }

            String did = "did:sludi:" + request.getDid();

            CitizenUser user = userRepository.findByAnyHash(null, null, HashUtil.sha256(did));
            if (user == null) {
                log.error("User not found for DID: {}", request.getDid());
                throw new SludiException(ErrorCodes.USER_NOT_FOUND);
            }

            AddressDto addressDto = mapToAddressDto(user);
            CredentialSubject credentialSubject = mapToCredentialSubject(user, addressDto);

            String credentialSubjectJson = objectMapper.writeValueAsString(credentialSubject);
            String credentialSubjectHash = cryptographyService.encryptData(credentialSubjectJson);

            List<SupportingDocumentResponseDto> supportingDocuments = mapSupportingDocuments(
                    user, request.getSupportingDocuments(), request.getCredentialType()
            );

            // Create credential ID
            String credentialId = "credential:" + request.getCredentialType().toLowerCase() + ":" + request.getDid();

            // Get expire date
            String expireDate = getExpirationDate(LocalDateTime.now(), 25);

            // CONVERT CredentialSubject to Claims Map
            Map<String, Object> claims = claimsMapper.convertToClaimsMap(credentialSubject);

            // Create signature request with claims
            CredentialSignatureRequestDto credentialSignatureRequestDto = CredentialSignatureRequestDto.builder()
                    .credentialId(credentialId)
                    .credentialType(request.getCredentialType())
                    .subjectDid(did)
                    .claims(claims)
                    .expirationDate(expireDate)
                    .build();

            // Create Proof of Data
            // Sign the credential with claims
            ProofData proofData = digitalSignatureService.signVerifiableCredential(
                    credentialSignatureRequestDto,
                    adminUser
            );

            ProofDataDto proofDataDto = ProofDataDto.builder()
                    .proofType(proofData.getProofType())
                    .creator(proofData.getCreator())
                    .created(proofData.getCreated())
                    .issuerDid(proofData.getIssuerDid())
                    .signatureValue(proofData.getSignatureValue())
                    .build();

            CredentialIssuanceRequestDto issuanceRequest = CredentialIssuanceRequestDto.builder()
                    .credentialId(credentialId)
                    .subjectDID(user.getDidId())
                    .issuerDID(proofDataDto.getIssuerDid())
                    .credentialType(request.getCredentialType())
                    .credentialSubjectHash(credentialSubjectHash)
                    .supportingDocuments(supportingDocuments)
                    .proofData(proofDataDto)
                    .expireDate(expireDate)
                    .build();

            log.info("Sending credential issuance request to Hyperledger for DID: {}", user.getDidId());

            VCBlockChainResult result = hyperledgerService.issueCredential(issuanceRequest);

            VerifiableCredential vc = VerifiableCredential.builder()
                    .id(result.getId())
                    .subjectDid(result.getSubjectDID())
                    .credentialType(result.getCredentialType())
                    .issuanceDate(result.getIssuanceDate())
                    .expirationDate(result.getExpirationDate())
                    .status(result.getStatus())
                    .proof(proofData)
                    .blockchainTxId(result.getBlockchainTxId())
                    .blockNumber(result.getBlockNumber())
                    .credentialSubjectHash(result.getCredentialSubjectHash())
                    .build();

            verifiableCredentialRepository.save(vc);

            log.info("VC issued successfully. CredentialId: {}, TxId: {}", result.getId(), result.getBlockchainTxId());

            return VCIssuedResponseDto.builder()
                    .credentialId(result.getId())
                    .subjectDID(result.getSubjectDID())
                    .credentialType(result.getCredentialType())
                    .status(result.getStatus())
                    .message("Identity Verifiable Credential issued successfully")
                    .blockchainTxId(result.getBlockchainTxId())
                    .build();
        } catch (SludiException e) {
            log.error("Business error during VC issuance: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error while issuing VC for DID: {}. Error: {}", request.getDid(), e.getMessage());
            throw new SludiException(ErrorCodes.FAILED_TO_ISSUE_IDENTITY_VC, e);
        }
    }

    public VCIssuedResponseDto issueDrivingLicenseVC(
            IssueDrivingLicenseVCRequestDto request,
            String userName) {

        log.info("Issuing driving license VC for DID: {}", request.getDid());

        try {
            // Find user
            OrganizationUser adminUser = organizationUserRepository.findByUsername(userName)
                    .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

            // Check if user has permission to issue driving license
            if (!organizationUserService.verifyUserPermission(userName, "license:issue")) {
                log.warn("User {} attempted to issue driving license without permission", userName);
                throw new SludiException(ErrorCodes.INSUFFICIENT_PERMISSIONS);
            }

            // Verify user is active
            if (adminUser.getStatus() != UserStatus.ACTIVE) {
                log.warn("Inactive user {} attempted to issue driving license", userName);
                throw new SludiException(ErrorCodes.USER_INACTIVE);
            }

            // Validate citizen and existing identity VC
            CitizenUser citizen = validateCitizenForDrivingLicense(request.getDid());

            // Validate driving license requirements
            validateDrivingLicenseRequirements(request);

            // Check for existing driving license
            if (
                    verifiableCredentialRepository.findBySubjectDidAndCredentialType(
                            request.getDid(), CredentialsType.DRIVING_LICENSE.toString()).isPresent()
            ) {
                throw new SludiException(ErrorCodes.DRIVING_LICENSE_ALREADY_EXISTS);
            }

            // Store supporting documents (test certificates, medical reports)
            List<SupportingDocumentResponseDto> supportingDocs =
                    mapSupportingDocuments(citizen, request.getSupportingDocuments(), CredentialsType.DRIVING_LICENSE.toString());

            // Generate license number
            String drivingLicenseNumber = licenseNumberGenerator.generateLicenseNumber();

            // Get expire date
            String expireDate = getExpirationDate(LocalDateTime.now(), request.getValidityYears());

            // Build credential subject
            DrivingLicenseCredentialSubject credentialSubject = buildDrivingLicenseCredentialSubject(
                    citizen, request, drivingLicenseNumber, LocalDate.now().toString(), expireDate
            );

            // Encrypt and hash credential subject
            String credentialSubjectJson =
                    objectMapper.writeValueAsString(credentialSubject);
            String credentialSubjectHash =
                    cryptographyService.encryptData(credentialSubjectJson);

            // Generate credential ID
            String credentialId = String.format("credential:%s:%s:%s",CredentialsType.DRIVING_LICENSE,
                    request.getDid(), drivingLicenseNumber);

            // Convert to claims and create proof
            Map<String, Object> claims =
                    claimsMapper.convertLicenseClaimsMap(credentialSubject);

            CredentialSignatureRequestDto signatureRequest =
                    CredentialSignatureRequestDto.builder()
                            .credentialId(credentialId)
                            .credentialType(CredentialsType.DRIVING_LICENSE.toString())
                            .subjectDid(request.getDid())
                            .claims(claims)
                            .expirationDate(expireDate)
                            .build();

            ProofData proofData = digitalSignatureService
                    .signVerifiableCredential(signatureRequest, adminUser);

            // Issue credential on blockchain
            CredentialIssuanceRequestDto issuanceRequest =
                    buildIssuanceRequest(credentialId, citizen, credentialSubjectHash, supportingDocs, proofData, expireDate);

            VCBlockChainResult result =
                    hyperledgerService.issueCredential(issuanceRequest);

            // Save credential and license records
            VerifiableCredential vc = VerifiableCredential.builder()
                    .id(result.getId())
                    .subjectDid(result.getSubjectDID())
                    .credentialType(result.getCredentialType())
                    .issuanceDate(result.getIssuanceDate())
                    .expirationDate(result.getExpirationDate())
                    .status(result.getStatus())
                    .proof(proofData)
                    .blockchainTxId(result.getBlockchainTxId())
                    .blockNumber(result.getBlockNumber())
                    .credentialSubjectHash(result.getCredentialSubjectHash())
                    .build();

            verifiableCredentialRepository.save(vc);

            log.info("Driving license VC issued successfully. CredentialId: {}",
                    result.getId());

            return VCIssuedResponseDto.builder()
                    .credentialId(result.getId())
                    .subjectDID(result.getSubjectDID())
                    .credentialType(result.getCredentialType())
                    .status(result.getStatus())
                    .message("Driving License Verifiable Credential issued successfully")
                    .blockchainTxId(result.getBlockchainTxId())
                    .build();

        } catch (Exception e) {
            log.error("Failed to issue driving license VC: {}", e.getMessage());
            throw new SludiException(
                    ErrorCodes.FAILED_TO_ISSUE_DRIVING_LICENSE_VC, e);
        }
    }

    /**
     * Get Identity Verifiable Credential (IVC) for a user
     * This method retrieves the IVC for a user based on their DID ID.
     */
    public VerifiableCredentialDto getVerifiableCredential(String credentialId) {
        log.info("Fetching Verifiable Credential for ID: {}", credentialId);

        try {
            if (credentialId == null || credentialId.trim().isEmpty()) {
                log.error("Attempt to fetch credential with null/empty ID.");
                throw new SludiException(ErrorCodes.CREDENTIAL_NOT_FOUND, "Credential ID cannot be null or empty");
            }

            log.info("Querying blockchain for credentialId: {}", credentialId);
            VCBlockChainResult vcBlockChainResult = hyperledgerService.readCredential(credentialId);

            if (vcBlockChainResult == null) {
                log.error("No credential found on blockchain for ID: {}", credentialId);
                throw new SludiException(ErrorCodes.CREDENTIAL_NOT_FOUND, "No credential found for ID: " + credentialId);
            }

            log.info("Decrypting credential subject for credentialId: {}", credentialId);
            String credentialSubjectJson = cryptographyService.decryptData(vcBlockChainResult.getCredentialSubjectHash());

            CredentialSubject credentialSubject;
            try {
                credentialSubject = objectMapper.readValue(credentialSubjectJson, CredentialSubject.class);
            } catch (Exception parseEx) {
                log.error("Failed to parse CredentialSubject JSON for credentialId: {}. Error: {}", credentialId, parseEx.getMessage());
                throw new SludiException(ErrorCodes.FAILED_TO_RETRIEVE_IDENTITY_VC, "Invalid credential subject format", parseEx);
            }

            log.info("Successfully retrieved Verifiable Credential for ID: {}", credentialId);

            return VerifiableCredentialDto.builder()
                    .id(vcBlockChainResult.getId())
                    .context(vcBlockChainResult.getContext())
                    .credentialType(vcBlockChainResult.getCredentialType())
                    .issuer(vcBlockChainResult.getIssuer())
                    .issuanceDate(vcBlockChainResult.getIssuanceDate())
                    .expirationDate(vcBlockChainResult.getExpirationDate())
                    .subjectDID(vcBlockChainResult.getSubjectDID())
                    .supportingDocuments(vcBlockChainResult.getSupportingDocuments())
                    .credentialSubject(credentialSubject)
                    .status(vcBlockChainResult.getStatus())
                    .proof(vcBlockChainResult.getProof())
                    .createdAt(vcBlockChainResult.getCreatedAt())
                    .updatedAt(vcBlockChainResult.getUpdatedAt())
                    .blockchainTxId(vcBlockChainResult.getBlockchainTxId())
                    .blockNumber(vcBlockChainResult.getBlockNumber())
                    .revokedBy(vcBlockChainResult.getRevokedBy())
                    .revocationReason(vcBlockChainResult.getRevocationReason())
                    .revokedAt(vcBlockChainResult.getRevokedAt())
                    .revocationTxId(vcBlockChainResult.getRevocationTxId())
                    .revocationBlockNumber(vcBlockChainResult.getRevocationBlockNumber())
                    .build();

        } catch (SludiException e) {
            log.error("Business exception while fetching VC for credentialId: {}. Error: {}", credentialId, e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error while fetching VC for credentialId: {}. Error: {}", credentialId, e.getMessage());
            throw new SludiException(ErrorCodes.FAILED_TO_RETRIEVE_IDENTITY_VC, "Unexpected error retrieving VC", e);
        }
    }

    public Map<String, String> getVehicleCategoryDescriptions() {
        Map<String, String> categories = new HashMap<>();

        // Category A and P - Motorcycles and Mopeds
        categories.put("P", "Moped - 2 wheeled, max 30mph, max 250kg, max 50cc");
        categories.put("A1", "Light motorcycle - max 153kg, max 11kW, max 125cc");
        categories.put("A", "Heavy motorcycle - 2 wheeled, max 410kg");

        // Category B - Cars and Light Vehicles
        categories.put("B1", "Motor tricycle - 3 wheeled, max 500kg, over 30mph");
        categories.put("B", "Car or light van - max 3,500kg, max 9 seats, trailer up to 750kg");
        categories.put("BE", "Car/light van with trailer over 750kg");

        // Category C - Goods Vehicles
        categories.put("C1", "Medium goods vehicle - 3,501-7,500kg, max 9 seats, trailer up to 750kg");
        categories.put("C", "Heavy goods vehicle - over 7,500kg, trailer up to 750kg");
        categories.put("C1E", "Medium goods with trailer over 750kg (combined max 12,000kg)");
        categories.put("CE", "Heavy goods with trailer over 750kg");

        // Category D - Passenger Vehicles
        categories.put("D1", "Minibus - 9-17 seats (not for hire), trailer up to 750kg");
        categories.put("D", "Bus or coach - over 17 seats or 9+ seats for hire, trailer up to 750kg");
        categories.put("D1E", "Minibus with trailer over 750kg (combined max 12,000kg)");
        categories.put("DE", "Bus/coach with trailer over 750kg");

        // Category F, H and K - Special Vehicles
        categories.put("F", "Agricultural tractor");
        categories.put("H", "Track-laying vehicle steered by its own tracks");
        categories.put("K", "Mowing machine or pedestrian controlled vehicle");

        return categories;
    }

    private AddressDto mapToAddressDto(CitizenUser user) {
        return AddressDto.builder()
                .street(user.getAddress().getStreet())
                .city(user.getAddress().getCity())
                .district(user.getAddress().getDistrict())
                .postalCode(user.getAddress().getPostalCode())
                .divisionalSecretariat(user.getAddress().getDivisionalSecretariat())
                .gramaNiladhariDivision(user.getAddress().getGramaNiladhariDivision())
                .province(user.getAddress().getProvince())
                .build();
    }

    private CredentialSubject mapToCredentialSubject(CitizenUser user, AddressDto addressDto) {
        return CredentialSubject.builder()
                .id(user.getDidId())
                .fullName(user.getFullName())
                .nic(user.getNic())
                .age(user.getAge())
                .dateOfBirth(user.getDateOfBirth().toString())
                .citizenship(user.getCitizenship())
                .gender(user.getGender())
                .nationality(user.getNationality())
                .bloodGroup(user.getBloodGroup())
                .address(addressDto)
                .build();
    }

    private List<SupportingDocumentResponseDto> mapSupportingDocuments(
            CitizenUser user, List<SupportingDocumentRequestDto> documents, String credentialType) {
        List<SupportingDocumentResponseDto> supportingDocuments = new ArrayList<>();

        if (documents != null && !documents.isEmpty()) {
            for (SupportingDocumentRequestDto doc : documents) {
                String hash = storeFileToIPFS(user.getId(), credentialType, doc);
                supportingDocuments.add(SupportingDocumentResponseDto.builder()
                        .name(doc.getName())
                        .fileType(doc.getType())
                        .side(doc.getSide())
                        .ipfsCid(hash)
                        .build());
                recordIPFSContent(user.getId(), hash, "document", "user_document", doc.getType());
            }
            log.info("Stored {} supporting documents in IPFS.", supportingDocuments.size());
        }

        return supportingDocuments;
    }

    /**
     * Uploads a document to IPFS and returns the CID/hash
     */
    private String storeFileToIPFS(UUID userId, String credentialType, SupportingDocumentRequestDto doc) {
        try {
            String path = String.format("%s/%s/%s", userId, credentialType, doc.getName());
            byte[] fileBytes = doc.getFile().getBytes();
            return ipfsIntegration.storeFile(path, fileBytes);
        } catch (Exception e) {
            throw new RuntimeException("Failed to store document on IPFS: " + e.getMessage(), e);
        }
    }

    /**
     * Records metadata about uploaded IPFS content in DB.
     */
    private void recordIPFSContent(UUID userId, String ipfsHash, String category, String subcategory, String mimeType) {
        log.debug("Recording IPFS content for user {} with hash {}", userId, ipfsHash);

        IPFSContent content = IPFSContent.builder()
                .id(UUID.randomUUID())
                .ipfsHash(ipfsHash)
                .ownerUserId(userId)
                .category(category)
                .subcategory(subcategory)
                .mimeType(mimeType)
                .accessLevel("private")
                .isEncrypted(true)
                .encryptionAlgorithm("SHA-256")
                .uploadedAt(LocalDateTime.now())
                .build();

        ipfsContentRepository.save(content);

        log.info("IPFS content recorded for user {}. Hash: {}", userId, ipfsHash);
    }

    private CitizenUser validateCitizenForDrivingLicense(String did) {
        String id = "did:sludi:" + did;
        CitizenUser citizen = userRepository.findByAnyHash(
                null, null, HashUtil.sha256(id));

        if (citizen == null) {
            throw new SludiException(ErrorCodes.USER_NOT_FOUND);
        }

        VerifiableCredential verifiableCredential = verifiableCredentialRepository.findBySubjectDidAndCredentialType(
                citizen.getDidId(), CredentialsType.IDENTITY.toString()).orElseThrow(() -> new SludiException(ErrorCodes.IDENTITY_CREDENTIAL_REQUIRED)
        );

        // Age verification (must be 18+)
        if (citizen.getAge() < 18) {
            throw new SludiException(
                    ErrorCodes.AGE_REQUIREMENT_NOT_MET,
                    "Must be 18 or older to obtain driving license");
        }

        return citizen;
    }

    private void validateDrivingLicenseRequirements(
            IssueDrivingLicenseVCRequestDto request) {

        // Validate vehicle categories
        if (request.getVehicleCategories() == null ||
                request.getVehicleCategories().isEmpty()) {
            throw new SludiException(
                    ErrorCodes.VEHICLE_CATEGORIES_REQUIRED);
        }

        // Validate required documents
        if(request.getSupportingDocuments().isEmpty()) {
            throw new SludiException(
                    ErrorCodes.REQUIRED_DOCUMENT_MISSING);
        }
    }

    private DrivingLicenseCredentialSubject buildDrivingLicenseCredentialSubject(
            CitizenUser citizen,
            IssueDrivingLicenseVCRequestDto request,
            String licenseNumber,
            String issueDate,
            String expiryDate) {

        // Build address string
        String fullAddress = buildFullAddress(citizen.getAddress());

        // Map vehicle categories from request
        List<VehicleCategory> authorizedVehicles = request.getVehicleCategories().stream()
                .map(this::mapToVehicleCategory)
                .collect(Collectors.toList());

        return DrivingLicenseCredentialSubject.builder()
                .id(citizen.getDidId())
                .fullName(citizen.getFullName())
                .nic(citizen.getNic())
                .dateOfBirth(citizen.getDateOfBirth().toString())
                .address(fullAddress)
                .profilePhoto(citizen.getProfilePhotoIpfsHash())
                .licenseNumber(licenseNumber)
                .issueDate(issueDate)
                .expiryDate(expiryDate)
                .authorizedVehicles(authorizedVehicles)
                .issuingAuthority(request.getIssuingAuthority() != null ?
                        request.getIssuingAuthority() : "Department of Motor Traffic, Sri Lanka")
                .restrictions(request.getRestrictions())
                .endorsements(request.getEndorsements())
                .bloodGroup(citizen.getBloodGroup())
                .build();
    }

    /**
     * Build full address string from AddressDto
     */
    private String buildFullAddress(Address address) {
        if (address == null) {
            return null;
        }

        List<String> addressParts = new ArrayList<>();

        if (address.getStreet() != null) addressParts.add(address.getStreet());
        if (address.getCity() != null) addressParts.add(address.getCity());
        if (address.getDistrict() != null) addressParts.add(address.getDistrict());
        if (address.getPostalCode() != null) addressParts.add(address.getPostalCode());
        if (address.getProvince() != null) addressParts.add(address.getProvince());

        return String.join(", ", addressParts);
    }

    /**
     * Map VehicleCategoryRequestDto to VehicleCategory for credential subject
     */
    private VehicleCategory mapToVehicleCategory(VehicleCategoryRequestDto dto) {
        return VehicleCategory.builder()
                .category(dto.getCategory().toUpperCase())
                .validFrom(dto.getValidFrom() != null ? dto.getValidFrom().toString() : LocalDate.now().toString())
                .validUntil(dto.getValidUntil().toString())
                .restrictions(dto.getRestrictions())
                .build();
    }

    private CredentialIssuanceRequestDto buildIssuanceRequest(
            String credentialId,
            CitizenUser citizen,
            String credentialSubjectHash,
            List<SupportingDocumentResponseDto> supportingDocs,
            ProofData proofData,
            String expireDate) {

        // Convert ProofData to ProofDataDto
        ProofDataDto proofDataDto = ProofDataDto.builder()
                .proofType(proofData.getProofType())
                .creator(proofData.getCreator())
                .created(proofData.getCreated())
                .issuerDid(proofData.getIssuerDid())
                .signatureValue(proofData.getSignatureValue())
                .build();

        return CredentialIssuanceRequestDto.builder()
                .credentialId(credentialId)
                .subjectDID(citizen.getDidId())
                .issuerDID(proofDataDto.getIssuerDid())
                .credentialType(CredentialsType.DRIVING_LICENSE.toString())
                .credentialSubjectHash(credentialSubjectHash)
                .supportingDocuments(supportingDocs)
                .expireDate(expireDate)
                .proofData(proofDataDto)
                .build();
    }

    /**
     * Check if the vehicle categories include heavy vehicles
     * Heavy vehicles include categories C, C1, D, D1, CE, C1E, DE, D1E
     */
    private boolean containsHeavyVehicle(List<VehicleCategoryRequestDto> vehicleCategories) {
        if (vehicleCategories == null || vehicleCategories.isEmpty()) {
            return false;
        }

        // Define heavy vehicle categories
        Set<String> heavyVehicleCategories = Set.of(
                "C",
                "C1",
                "D",
                "D1",
                "CE",
                "C1E",
                "DE",
                "D1E"
        );

        return vehicleCategories.stream()
                .anyMatch(category -> heavyVehicleCategories.contains(
                        category.getCategory().toUpperCase()));
    }

    private String getExpirationDate(LocalDateTime dateTime, int validYear) {
        dateTime = dateTime.plusYears(validYear);
        return dateTime.toString();
    }
}
