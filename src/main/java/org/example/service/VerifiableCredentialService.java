package org.example.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.*;
import org.example.entity.*;
import org.example.enums.CredentialsType;
import org.example.enums.PresentationStatus;
import org.example.enums.UserStatus;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.example.integration.IPFSIntegration;
import org.example.repository.*;
import org.example.security.CryptographyService;
import org.example.utils.CredentialClaimsMapper;
import org.example.utils.HashUtil;
import org.example.utils.LicenseNumberGenerator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@Transactional
public class VerifiableCredentialService {

    @Value("${spring.base.url}")
    private String baseUrl;

    private final HyperledgerService hyperledgerService;
    private final CryptographyService cryptographyService;
    private final DigitalSignatureService digitalSignatureService;
    private final IPFSIntegration ipfsIntegration;
    private final CredentialClaimsMapper claimsMapper;
    private final LicenseNumberGenerator licenseNumberGenerator;
    private final OrganizationUserService organizationUserService;
    private final QRCodeService qrCodeService;
    private final OrganizationUserRepository organizationUserRepository;
    private final VerifiableCredentialRepository verifiableCredentialRepository;
    private final CitizenUserRepository userRepository;
    private final IPFSContentRepository ipfsContentRepository;
    private final PresentationRequestRepository presentationRequestRepository;
    private final WalletVerifiableCredentialRepository walletVerifiableCredentialRepository;
    private final WalletRepository walletRepository;

    private final ObjectMapper objectMapper = new ObjectMapper();

    public VerifiableCredentialService(
            HyperledgerService hyperledgerService,
            CryptographyService cryptographyService,
            DigitalSignatureService digitalSignatureService,
            IPFSIntegration ipfsIntegration,
            LicenseNumberGenerator licenseNumberGenerator, QRCodeService qrCodeService,
            VerifiableCredentialRepository verifiableCredentialRepository,
            CitizenUserRepository userRepository,
            IPFSContentRepository ipfsContentRepository,
            CredentialClaimsMapper claimsMapper,
            OrganizationUserService organizationUserService,
            OrganizationUserRepository organizationUserRepository,
            PresentationRequestRepository presentationRequestRepository,
            WalletVerifiableCredentialRepository walletVerifiableCredentialRepository,
            WalletRepository walletRepository) {
        this.hyperledgerService = hyperledgerService;
        this.cryptographyService = cryptographyService;
        this.digitalSignatureService = digitalSignatureService;
        this.ipfsIntegration = ipfsIntegration;
        this.licenseNumberGenerator = licenseNumberGenerator;
        this.qrCodeService = qrCodeService;
        this.verifiableCredentialRepository = verifiableCredentialRepository;
        this.userRepository = userRepository;
        this.ipfsContentRepository = ipfsContentRepository;
        this.claimsMapper = claimsMapper;
        this.organizationUserService = organizationUserService;
        this.organizationUserRepository = organizationUserRepository;
        this.presentationRequestRepository = presentationRequestRepository;
        this.walletVerifiableCredentialRepository = walletVerifiableCredentialRepository;
        this.walletRepository = walletRepository;
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
                    user, request.getSupportingDocuments(), request.getCredentialType());

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
                    .signData(credentialSubjectHash)
                    .expirationDate(expireDate)
                    .build();

            // Create Proof of Data
            // Sign the credential with claims
            ProofData proofData = digitalSignatureService.signVerifiableCredential(
                    credentialSignatureRequestDto,
                    adminUser);

            ProofDataDto proofDataDto = ProofDataDto.builder()
                    .proofType(proofData.getProofType())
                    .creator(proofData.getCreator())
                    .created(proofData.getCreated())
                    .issuerDid(proofData.getIssuerDid())
                    .signatureValue(proofData.getSignatureValue())
                    .build();

            List<String> context = List.of(
                    "https://www.w3.org/2018/credentials/v1",
                    "https://sludi.gov.lk/contexts/identity/v1");

            CredentialIssuanceRequestDto issuanceRequest = CredentialIssuanceRequestDto.builder()
                    .context(context)
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

            List<CredentialClaim> claimEntities = claims.entrySet().stream()
                    .map(entry -> {
                        try {
                            String claimName = entry.getKey();
                            String normalized = normalizeValue(entry.getValue());
                            String claimHash = HashUtil.sha256(normalized);

                            return CredentialClaim.builder()
                                    .claimName(claimName)
                                    .claimHash(claimHash)
                                    .credential(vc)
                                    .build();
                        } catch (Exception e) {
                            throw new RuntimeException("Failed to hash claim: " + entry.getKey(), e);
                        }
                    })
                    .collect(Collectors.toList());

            vc.setClaims(claimEntities);

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
                throw new SludiException(ErrorCodes.CREDENTIAL_NOT_FOUND,
                        "No credential found for ID: " + credentialId);
            }

            log.info("Decrypting credential subject for credentialId: {}", credentialId);
            String credentialSubjectJson = cryptographyService
                    .decryptData(vcBlockChainResult.getCredentialSubjectHash());

            CredentialSubject credentialSubject;
            try {
                credentialSubject = objectMapper.readValue(credentialSubjectJson, CredentialSubject.class);
            } catch (Exception parseEx) {
                log.error("Failed to parse CredentialSubject JSON for credentialId: {}. Error: {}", credentialId,
                        parseEx.getMessage());
                throw new SludiException(ErrorCodes.FAILED_TO_RETRIEVE_IDENTITY_VC, "Invalid credential subject format",
                        parseEx);
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
            log.error("Business exception while fetching VC for credentialId: {}. Error: {}", credentialId,
                    e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error while fetching VC for credentialId: {}. Error: {}", credentialId,
                    e.getMessage());
            throw new SludiException(ErrorCodes.FAILED_TO_RETRIEVE_IDENTITY_VC, "Unexpected error retrieving VC", e);
        }
    }

    /**
     * Initiates the driving license issuance process by generating a QR code
     * that the citizen scans with their identity wallet
     */
    public DrivingLicenseRequestResponseDto initiateDrivingLicenseRequest(String userName) {
        log.info("Initiating driving license request by user: {}", userName);

        try {
            // Verify officer permissions
            OrganizationUser officer = organizationUserRepository.findByUsername(userName)
                    .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

            if (!organizationUserService.verifyUserPermission(userName, "license:request_citizen_data")) {
                log.warn("User {} attempted to request citizen data without permission", userName);
                throw new SludiException(ErrorCodes.INSUFFICIENT_PERMISSIONS);
            }

            if (officer.getStatus() != UserStatus.ACTIVE) {
                log.warn("Inactive user {} attempted to request citizen data", userName);
                throw new SludiException(ErrorCodes.USER_INACTIVE);
            }

            // Generate unique session ID
            String sessionId = UUID.randomUUID().toString();

            // Get department
            String departmentDid = officer.getOrganization().getOrgCode();

            // Create presentation request
            PresentationRequest presentationRequest = PresentationRequest.builder()
                    .id(UUID.randomUUID())
                    .sessionId(sessionId)
                    .requesterId(departmentDid)
                    .requesterName("Department of Motor Traffic")
                    .requestedAttributes(Arrays.asList(
                            "fullName",
                            "dateOfBirth",
                            "age",
                            "address",
                            "bloodGroup",
                            "id",
                            "nic",
                            "profilePhoto"))
                    .purpose("Driving License Issuance")
                    .status(PresentationStatus.PENDING.name())
                    .createdAt(LocalDateTime.now())
                    .expiresAt(LocalDateTime.now().plusMinutes(15))
                    .createdBy(officer.getUsername())
                    .build();

            presentationRequestRepository.save(presentationRequest);

            // Generate QR code URL
            String requestUrl = String.format(
                    "%s/api/wallet/driving-license/request/%s",
                    baseUrl,
                    sessionId);

            // Generate QR code image
            byte[] qrCodeImage = qrCodeService.generateQRCode(requestUrl, 300, 300);

            log.info("Driving license request initiated. SessionId: {}", sessionId);

            return DrivingLicenseRequestResponseDto.builder()
                    .sessionId(sessionId)
                    .requestUrl(requestUrl)
                    .qrCode(Base64.getEncoder().encodeToString(qrCodeImage))
                    .expiresAt(presentationRequest.getExpiresAt())
                    .message("QR code generated. Citizen should scan with identity wallet.")
                    .build();

        } catch (Exception e) {
            log.error("Failed to initiate driving license request: {}", e.getMessage());
            throw new SludiException(ErrorCodes.FAILED_TO_INITIATE_LICENSE_REQUEST, e);
        }
    }

    /**
     * Wallet calls this endpoint after scanning QR code to get the presentation
     * request details
     */
    public PresentationRequestDto getPresentationRequest(String sessionId) {
        log.info("Retrieving presentation request for sessionId: {}", sessionId);

        try {
            PresentationRequest request = presentationRequestRepository
                    .findBySessionId(sessionId)
                    .orElseThrow(() -> new SludiException(ErrorCodes.PRESENTATION_REQUEST_NOT_FOUND));

            // Check if expired
            if (request.getExpiresAt().isBefore(LocalDateTime.now())) {
                request.setStatus(PresentationStatus.EXPIRED.name());
                presentationRequestRepository.save(request);
                throw new SludiException(ErrorCodes.PRESENTATION_REQUEST_EXPIRED);
            }

            // Check if already fulfilled
            if (PresentationStatus.FULFILLED.name().equals(request.getStatus())) {
                throw new SludiException(ErrorCodes.PRESENTATION_REQUEST_ALREADY_FULFILLED);
            }

            return PresentationRequestDto.builder()
                    .sessionId(request.getSessionId())
                    .requesterId(request.getRequesterId())
                    .requesterName(request.getRequesterName())
                    .requestedAttributes(request.getRequestedAttributes())
                    .purpose(request.getPurpose())
                    .expiresAt(request.getExpiresAt())
                    .build();

        } catch (SludiException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to retrieve presentation request: {}", e.getMessage());
            throw new SludiException(ErrorCodes.FAILED_TO_RETRIEVE_PRESENTATION_REQUEST, e);
        }
    }

    /**
     * Wallet submits the citizen's data as a Verifiable Presentation
     * after citizen approves in their wallet
     */
    public VerifiablePresentationResponseDto submitVerifiablePresentation(
            String sessionId,
            VerifiablePresentationDto vpDto) {

        log.info("Receiving verifiable presentation for sessionId: {}", sessionId);

        try {
            // Find presentation request
            PresentationRequest request = presentationRequestRepository
                    .findBySessionId(sessionId)
                    .orElseThrow(() -> new SludiException(ErrorCodes.PRESENTATION_REQUEST_NOT_FOUND));

            // Verify request is still valid
            if (request.getExpiresAt().isBefore(LocalDateTime.now())) {
                throw new SludiException(ErrorCodes.PRESENTATION_REQUEST_EXPIRED);
            }

            if (PresentationStatus.FULFILLED.name().equals(request.getStatus())) {
                throw new SludiException(ErrorCodes.PRESENTATION_REQUEST_ALREADY_FULFILLED);
            }

            // Verify VP signature
            boolean vpSignatureValid = digitalSignatureService.verifyVPSignature(sessionId, vpDto);
            if (!vpSignatureValid) {
                log.error("Invalid VP signature for sessionId: {}", sessionId);
                throw new SludiException(ErrorCodes.INVALID_VP_SIGNATURE);
            }

            // Verify the holder owns the DID (proof of possession)
            boolean didOwnershipValid = digitalSignatureService.verifyDIDOwnership(
                    vpDto.getHolder(),
                    vpDto.getProof());
            if (!didOwnershipValid) {
                log.error("Invalid DID ownership proof for sessionId: {}", sessionId);
                throw new SludiException(ErrorCodes.INVALID_DID_OWNERSHIP);
            }

            // Verify the included VC is valid and signed by trusted issuer
            VerifiableCredential credential = verifiableCredentialRepository.findById(vpDto.getCredentialId())
                    .orElseThrow(() -> new SludiException(ErrorCodes.CREDENTIAL_NOT_FOUND));

             boolean vcValid = verifyIncludedCredential(credential);
             if (!vcValid) {
             log.error("Invalid or untrusted credential in VP for sessionId: {}",
             sessionId);
             throw new SludiException(ErrorCodes.INVALID_CREDENTIAL_IN_VP);
             }

             // Verify user sharedAttributes are valid
             verifySharedAttributes(vpDto, credential);

             // Verify all requested attributes are present
             verifyRequestedAttributes(request.getRequestedAttributes(), vpDto);

            // Store presentation data
            request.setStatus(PresentationStatus.FULFILLED.name());
            request.setFulfilledAt(LocalDateTime.now());
            request.setHolderDid(vpDto.getHolder());
            request.setSharedAttributes(vpDto.getAttributes());
            presentationRequestRepository.save(request);

            log.info("Verifiable presentation verified and stored for sessionId: {}", sessionId);

            return VerifiablePresentationResponseDto.builder()
                    .sessionId(sessionId)
                    .status("VERIFIED")
                    .message("Citizen data verified successfully. Proceed with driving license issuance.")
                    .build();

        } catch (SludiException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to process verifiable presentation: {}", e.getMessage());
            throw new SludiException(ErrorCodes.FAILED_TO_PROCESS_VP, e);
        }
    }

    /**
     * Officer dashboard polls this to check if citizen has submitted their data
     */
    public PresentationStatusDto checkPresentationStatus(String sessionId) {
        log.info("Checking presentation status for sessionId: {}", sessionId);

        try {
            PresentationRequest request = presentationRequestRepository
                    .findBySessionId(sessionId)
                    .orElseThrow(() -> new SludiException(ErrorCodes.PRESENTATION_REQUEST_NOT_FOUND));

            boolean canProceed = PresentationStatus.FULFILLED.name().equals(request.getStatus()) ||
                    "COMPLETED".equals(request.getStatus());

            Map<String, Object> sharedAttributes = Collections.emptyMap();
            if (canProceed && request.getSharedAttributes() != null) {
                sharedAttributes = request.getSharedAttributes();
            }

            return PresentationStatusDto.builder()
                    .sessionId(sessionId)
                    .status(request.getStatus())
                    .canProceed(canProceed)
                    .sharedAttributes(sharedAttributes)
                    .fulfilledAt(request.getFulfilledAt())
                    .expiresAt(request.getExpiresAt())
                    .build();

        } catch (Exception e) {
            log.error("Failed to check presentation status: {}", e.getMessage());
            throw new SludiException(ErrorCodes.FAILED_TO_CHECK_STATUS, e);
        }
    }

    public List<PresentationRequestResponseDto> getAllLicenseRequest() {
        try {
            List<PresentationRequest> presentationRequestList = presentationRequestRepository.findAll();

            return presentationRequestList.stream()
                    .map(this::mapPresentationRequestToDto)
                    .collect(Collectors.toList());

        } catch (Exception e) {
            throw new SludiException(ErrorCodes.FAILED_TO_GET_PRESENTATIONS, e.getMessage());
        }
    }

    /**
     * Issues the driving license credential after verifying citizen data through VP
     */
    public VCIssuedResponseDto issueDrivingLicenseVC(
            IssueDrivingLicenseVCRequestDto request,
            String userName) {

        log.info("Issuing driving license VC for sessionId: {}", request.getSessionId());

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

            // Retrieve fulfilled presentation request
            PresentationRequest presentationRequest = presentationRequestRepository
                    .findBySessionId(request.getSessionId())
                    .orElseThrow(() -> new SludiException(ErrorCodes.PRESENTATION_REQUEST_NOT_FOUND));

            if (!PresentationStatus.FULFILLED.name().equals(presentationRequest.getStatus())) {
                throw new SludiException(ErrorCodes.PRESENTATION_NOT_FULFILLED);
            }

            // Validate citizen and existing identity VC
            String citizenDid = presentationRequest.getHolderDid();

            CitizenUser citizen = userRepository.findByAnyHash(null, null, HashUtil.sha256(citizenDid));

            if (citizen == null) {
                log.error("User not found for DID: {}", citizenDid);
                throw new SludiException(ErrorCodes.USER_NOT_FOUND);
            }

            // Validate driving license requirements
            validateDrivingLicenseRequirements(request, presentationRequest);

            // Check for existing driving license
            if (verifiableCredentialRepository.findBySubjectDidAndCredentialType(
                    citizenDid, CredentialsType.DRIVING_LICENSE.toString()).isPresent()) {
                throw new SludiException(ErrorCodes.DRIVING_LICENSE_ALREADY_EXISTS);
            }

            // Store supporting documents (test certificates, medical reports)
            List<SupportingDocumentResponseDto> supportingDocs = mapSupportingDocuments(citizen,
                    request.getSupportingDocuments(), CredentialsType.DRIVING_LICENSE.toString());

            // Generate license number
            String drivingLicenseNumber = licenseNumberGenerator.generateLicenseNumber();

            // Get expire date
            String expireDate = getExpirationDate(LocalDateTime.now(), request.getValidityYears());

            // Build credential subject
            DrivingLicenseCredentialSubject credentialSubject = buildDrivingLicenseCredentialSubject(
                    request, presentationRequest, drivingLicenseNumber, LocalDate.now().toString(), expireDate);

            // Encrypt and hash credential subject
            String credentialSubjectJson = objectMapper.writeValueAsString(credentialSubject);
            String credentialSubjectHash = cryptographyService.encryptData(credentialSubjectJson);

            // Generate credential ID
            String credentialId = String.format(
                    "credential:%s:%s",
                    CredentialsType.DRIVING_LICENSE.name().toLowerCase(),
                    drivingLicenseNumber);

            // Convert to claims and create proof
            Map<String, Object> claims = claimsMapper.convertLicenseClaimsMap(credentialSubject);

            CredentialSignatureRequestDto signatureRequest = CredentialSignatureRequestDto.builder()
                    .credentialId(credentialId)
                    .credentialType(CredentialsType.DRIVING_LICENSE.toString())
                    .subjectDid(citizenDid)
                    .signData(credentialSubjectHash)
                    .expirationDate(expireDate)
                    .build();

            ProofData proofData = digitalSignatureService
                    .signVerifiableCredential(signatureRequest, adminUser);

            // Issue credential on blockchain
            CredentialIssuanceRequestDto issuanceRequest = buildIssuanceRequest(credentialId, citizen,
                    credentialSubjectHash, supportingDocs, proofData, expireDate);

            VCBlockChainResult result = hyperledgerService.issueCredential(issuanceRequest);

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

            List<CredentialClaim> claimEntities = claims.entrySet().stream()
                    .map(entry -> {
                        try {
                            String claimName = entry.getKey();
                            String normalized = normalizeValue(entry.getValue());
                            String claimHash = HashUtil.sha256(normalized);

                            return CredentialClaim.builder()
                                    .claimName(claimName)
                                    .claimHash(claimHash)
                                    .credential(vc)
                                    .build();
                        } catch (Exception e) {
                            throw new RuntimeException("Failed to hash claim: " + entry.getKey(), e);
                        }
                    })
                    .collect(Collectors.toList());

            vc.setClaims(claimEntities);

            verifiableCredentialRepository.save(vc);

            Wallet wallet = walletRepository.findByDidId(citizenDid)
                    .orElseThrow(() -> new SludiException(ErrorCodes.WALLET_NOT_FOUND));

            WalletVerifiableCredential walletVerifiableCredential = WalletVerifiableCredential.builder()
                    .encryptedCredential(vc.getCredentialSubjectHash())
                    .verifiableCredential(vc)
                    .addedAt(LocalDateTime.now())
                    .wallet(wallet)
                    .verified(true)
                    .build();

            walletVerifiableCredentialRepository.save(walletVerifiableCredential);

            presentationRequest.setStatus(PresentationStatus.COMPLETED.name());
            presentationRequest.setIssuedCredentialId(vc.getId());
            presentationRequest.setCompletedAt(LocalDateTime.now());
            presentationRequestRepository.save(presentationRequest);

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

    public DrivingLicenseStatsResponse getDrivingLicenseStats() {

        // Load all driving license credentials
        List<VerifiableCredential> licenses = verifiableCredentialRepository
                .getAllByCredentialType(CredentialsType.DRIVING_LICENSE.name());

        int total = licenses.size();

        int active = (int) licenses.stream()
                .filter(vc -> "active".equalsIgnoreCase(vc.getStatus()))
                .count();

        int deactivated = (int) licenses.stream()
                .filter(vc -> "deactivated".equalsIgnoreCase(vc.getStatus()) ||
                        "revoked".equalsIgnoreCase(vc.getStatus()))
                .count();

        // Expire within next 30 days
        LocalDate today = LocalDate.now();
        LocalDate soon = today.plusDays(30);

        int expireSoon = (int) licenses.stream()
                .map(VerifiableCredential::getExpirationDate)
                .filter(Objects::nonNull)
                .map(dateStr -> {
                    try {
                        return LocalDate.parse(dateStr); // expects YYYY-MM-DD
                    } catch (Exception e) {
                        return null; // invalid date format skip
                    }
                })
                .filter(Objects::nonNull)
                .filter(exp -> exp.isAfter(today) && exp.isBefore(soon))
                .count();

        return DrivingLicenseStatsResponse.builder()
                .totalDrivingLicense(total)
                .activeDrivingLicense(active)
                .deactivateDrivingLicense(deactivated)
                .expireSoon(expireSoon)
                .build();
    }

    /**
     * Verify the credential included in the VP is valid
     */
    private boolean verifyIncludedCredential(VerifiableCredential credential) {
        try {

            ProofDataDto proofDataDto = ProofDataDto.builder()
                    .proofType(credential.getProof().getProofType())
                    .created(credential.getProof().getCreated())
                    .creator(credential.getProof().getCreator())
                    .issuerDid(credential.getProof().getIssuerDid())
                    .signatureValue(credential.getProof().getSignatureValue())
                    .build();

            CredentialVerificationRequestDto requestDto = CredentialVerificationRequestDto.builder()
                    .credentialId(credential.getId())
                    .credentialType(credential.getCredentialType())
                    .subjectDid(credential.getSubjectDid())
                    .signData(credential.getCredentialSubjectHash())
                    .expirationDate(credential.getExpirationDate())
                    .proof(proofDataDto)
                    .build();

            CredentialVerificationResponseDto response = digitalSignatureService.verifyCredential(requestDto);

            return response.getSignatureValid();

        } catch (Exception e) {
            log.error("Error verifying credential: {}", e.getMessage());
            return false;
        }
    }

    private PresentationRequestResponseDto mapPresentationRequestToDto(PresentationRequest entity) {
        return PresentationRequestResponseDto.builder()
                .id(entity.getId())
                .sessionId(entity.getSessionId())
                .requesterId(entity.getRequesterId())
                .requesterName(entity.getRequesterName())
                .requestedAttributes(entity.getRequestedAttributes())
                .purpose(entity.getPurpose())
                .status(entity.getStatus())
                .createdAt(entity.getCreatedAt())
                .expiresAt(entity.getExpiresAt())
                .fulfilledAt(entity.getFulfilledAt())
                .completedAt(entity.getCompletedAt())
                .createdBy(entity.getCreatedBy())
                .holderDid(entity.getHolderDid())
                .sharedAttributes(entity.getSharedAttributes())
                .issuedCredentialId(entity.getIssuedCredentialId())
                .errorMessage(entity.getErrorMessage())
                .build();
    }

    /**
     * Verify that all requested attributes are present in the
     * VerifiablePresentationDto.
     */
    private static void verifyRequestedAttributes(List<String> requestedAttributes, VerifiablePresentationDto vpDto) {
        if (requestedAttributes == null || requestedAttributes.isEmpty()) {
            return; // Nothing to verify
        }

        if (vpDto == null || vpDto.getAttributes() == null) {
            throw new SludiException(ErrorCodes.VP_ATTRIBUTES_MISSING);
        }

        Map<String, Object> providedAttributes = vpDto.getAttributes();

        List<String> missingAttributes = requestedAttributes.stream()
                .filter(attr -> !providedAttributes.containsKey(attr) || providedAttributes.get(attr) == null)
                .collect(Collectors.toList());

        if (!missingAttributes.isEmpty()) {
            throw new SludiException(ErrorCodes.ATTRIBUTE_MISSING);
        }
    }

    /**
     * Verify that all attributes shared in the VP exist in the original Verifiable
     * Credential.
     * Throws exception if any attribute is invalid.
     */
    public static void verifySharedAttributes(VerifiablePresentationDto vpDto, VerifiableCredential credential)
            throws JsonProcessingException {
        if (vpDto.getAttributes() == null || vpDto.getAttributes().isEmpty()) {
            throw new SludiException(ErrorCodes.INVALID_VP_ATTRIBUTES);
        }

        // Build a map of claimName -> claimHash from the VC
        Map<String, String> validClaims = credential.getClaims().stream()
                .collect(Collectors.toMap(CredentialClaim::getClaimName, CredentialClaim::getClaimHash));

        String subjectDid = credential.getSubjectDid();

        log.info("Attributes: {}", vpDto.getAttributes());
        // Check each shared attribute
        for (Map.Entry<String, Object> entry : vpDto.getAttributes().entrySet()) {

            String claimName = entry.getKey();
            Object claimValue = entry.getValue();

            if (claimName.equalsIgnoreCase("id")
                    || claimName.equalsIgnoreCase("subjectId")
                    || claimName.equalsIgnoreCase("subjectDid")
                    || claimName.equalsIgnoreCase("userId")) {

                String providedId = normalizeValue(claimValue);

                if (!providedId.equals(subjectDid)) {
                    throw new SludiException(ErrorCodes.INVALID_VP_ATTRIBUTES,
                            "Shared subject ID/DID does not match the VC subject DID");
                }

                continue;
            }

            String normalizedSharedValue = normalizeValue(claimValue);
            String sharedHash = HashUtil.sha256(normalizedSharedValue);

            String originalHash = validClaims.get(claimName);

            if (!sharedHash.equals(originalHash)) {
                throw new SludiException(ErrorCodes.INVALID_VP_ATTRIBUTES,
                        "Attribute '" + claimName + "' value does not match the VC");
            }
        }
    }

    public byte[] getProfilePhoto(String cid) {
        byte[] data = ipfsIntegration.retrieveFile(cid);
        if (data == null || data.length == 0) {
            throw new SludiException(ErrorCodes.FILE_READ_ERROR, "No data found for CID: " + cid);
        }
        return data;
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
                .profilePhotoHash(user.getProfilePhotoIpfsHash())
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

    private void validateDrivingLicenseRequirements(
            IssueDrivingLicenseVCRequestDto request,
            PresentationRequest presentationRequest) {

        // Validate vehicle categories
        if (request.getVehicleCategories() == null ||
                request.getVehicleCategories().isEmpty()) {
            throw new SludiException(
                    ErrorCodes.VEHICLE_CATEGORIES_REQUIRED);
        }

        // Validate required documents
        if (request.getSupportingDocuments().isEmpty()) {
            throw new SludiException(
                    ErrorCodes.REQUIRED_DOCUMENT_MISSING);
        }

        Map<String, Object> attrs = presentationRequest.getSharedAttributes();

        Object ageObj = attrs.get("age");

        if (ageObj == null) {
            throw new SludiException(ErrorCodes.AGE_INFORMATION_MISSING);
        }

        // Convert age to integer safely
        int age;
        if (ageObj instanceof Number) {
            age = ((Number) ageObj).intValue();
        } else {
            try {
                age = Integer.parseInt(ageObj.toString());
            } catch (NumberFormatException e) {
                throw new SludiException(ErrorCodes.INVALID_AGE_FORMAT);
            }
        }

        // Age verification
        if (age < 18) {
            throw new SludiException(ErrorCodes.AGE_REQUIREMENT_NOT_MET);
        }
    }

    private DrivingLicenseCredentialSubject buildDrivingLicenseCredentialSubject(
            IssueDrivingLicenseVCRequestDto request,
            PresentationRequest presentationRequest,
            String licenseNumber,
            String issueDate,
            String expiryDate) throws JsonProcessingException {

        Map<String, Object> attrs = presentationRequest.getSharedAttributes();

        if (attrs == null || attrs.isEmpty()) {
            throw new SludiException(ErrorCodes.ATTRIBUTE_MISSING);
        }

        String fullName = String.valueOf(attrs.get("fullName"));
        String nic = String.valueOf(attrs.get("nic"));
        String dob = attrs.get("dob") != null ? attrs.get("dob").toString() : null;
        String bloodGroup = String.valueOf(attrs.get("bloodGroup"));
        String id = String.valueOf(attrs.get("id"));

        Object profilePhotoObj = attrs.get("profilePhoto");
        String profilePhoto = profilePhotoObj instanceof String
                ? (String) profilePhotoObj
                : objectMapper.writeValueAsString(profilePhotoObj);

        Object addressObj = attrs.get("address");
        String address = addressObj instanceof String
                ? (String) addressObj
                : objectMapper.writeValueAsString(addressObj);

        // Map vehicle categories from request
        List<VehicleCategory> authorizedVehicles = request.getVehicleCategories().stream()
                .map(this::mapToVehicleCategory)
                .collect(Collectors.toList());

        return DrivingLicenseCredentialSubject.builder()
                .id(id)
                .fullName(fullName)
                .nic(nic)
                .dateOfBirth(dob)
                .address(address)
                .profilePhoto(profilePhoto)
                .licenseNumber(licenseNumber)
                .issueDate(issueDate)
                .expiryDate(expiryDate)
                .authorizedVehicles(authorizedVehicles)
                .issuingAuthority(
                        request.getIssuingAuthority() != null
                                ? request.getIssuingAuthority()
                                : "Department of Motor Traffic, Sri Lanka")
                .restrictions(request.getRestrictions())
                .endorsements(request.getEndorsements())
                .bloodGroup(bloodGroup)
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

        if (address.getStreet() != null)
            addressParts.add(address.getStreet());
        if (address.getCity() != null)
            addressParts.add(address.getCity());
        if (address.getDistrict() != null)
            addressParts.add(address.getDistrict());
        if (address.getPostalCode() != null)
            addressParts.add(address.getPostalCode());
        if (address.getProvince() != null)
            addressParts.add(address.getProvince());

        return String.join(", ", addressParts);
    }

    /**
     * Map VehicleCategoryRequestDto to VehicleCategory for credential subject
     */
    private VehicleCategory mapToVehicleCategory(VehicleCategoryRequestDto dto) {

        VehicleCategory category = VehicleCategory.builder()
                .category(dto.getCategory().toUpperCase())
                .validFrom(dto.getValidFrom() != null ? dto.getValidFrom().toString() : LocalDate.now().toString())
                .restrictions(dto.getRestrictions())
                .build();

        LocalDate validUntil = dto.getValidUntil() != null
                ? dto.getValidUntil()
                : LocalDate.now().plusYears(5);
        category.setValidUntil(validUntil.toString());

        return category;
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

        List<String> context = List.of(
                "https://www.w3.org/2018/credentials/v1",
                "https://sludi.gov.lk/contexts/identity/v1");

        return CredentialIssuanceRequestDto.builder()
                .context(context)
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
     * Check if the vehicle categories include heavy vehicle
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
                "D1E");

        return vehicleCategories.stream()
                .anyMatch(category -> heavyVehicleCategories.contains(
                        category.getCategory().toUpperCase()));
    }

    private String getExpirationDate(LocalDateTime dateTime, int validYear) {
        return dateTime
                .plusYears(validYear)
                .atZone(ZoneOffset.UTC)
                .truncatedTo(ChronoUnit.MILLIS)
                .toInstant()
                .toString();
    }

    private static String normalizeValue(Object value) throws JsonProcessingException {
        if (value instanceof Map) {
            // sort keys to ensure deterministic order
            Map<String, Object> sorted = new TreeMap<>((Map) value);

            return new ObjectMapper().writeValueAsString(sorted);
        }
        return String.valueOf(value);
    }
}
