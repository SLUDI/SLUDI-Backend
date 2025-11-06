package org.example.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.example.dto.*;
import org.example.entity.CitizenUser;
import org.example.entity.ProofData;
import org.example.entity.VerifiableCredential;
import org.example.enums.ProofPurpose;
import org.example.exception.ErrorCodes;
import org.example.exception.SludiException;
import org.example.integration.IPFSIntegration;
import org.example.repository.CitizenUserRepository;
import org.example.repository.IPFSContentRepository;
import org.example.repository.VerifiableCredentialRepository;
import org.example.security.CryptographyService;
import org.example.utils.HashUtil;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@Transactional
public class VerifiableCredentialService {

    private final HyperledgerService hyperledgerService;
    private final CryptographyService cryptographyService;
    private final DigitalSignatureService digitalSignatureService;
    private final IPFSIntegration ipfsIntegration;
    private final VerifiableCredentialRepository verifiableCredentialRepository;
    private final CitizenUserRepository userRepository;
    private final IPFSContentRepository ipfsContentRepository;

    private final ObjectMapper objectMapper = new ObjectMapper();

    public VerifiableCredentialService(
            HyperledgerService hyperledgerService,
            CryptographyService cryptographyService,
            DigitalSignatureService digitalSignatureService,
            IPFSIntegration ipfsIntegration,
            VerifiableCredentialRepository verifiableCredentialRepository,
            CitizenUserRepository userRepository,
            IPFSContentRepository ipfsContentRepository
    ) {
        this.hyperledgerService = hyperledgerService;
        this.cryptographyService = cryptographyService;
        this.digitalSignatureService = digitalSignatureService;
        this.ipfsIntegration = ipfsIntegration;
        this.verifiableCredentialRepository = verifiableCredentialRepository;
        this.userRepository = userRepository;
        this.ipfsContentRepository = ipfsContentRepository;
    }

    public VCIssuedResponseDto issueVC(IssueVCRequestDto request) {
        log.info("Issuing identity VC for DID: {}, CredentialType: {}", request.getDid(), request.getCredentialType());

        try {
            CitizenUser user = userRepository.findByAnyHash(null, null, HashUtil.sha256(request.getDid()));
            if (user == null) {
                log.error("User not found for DID: {}", request.getDid());
                throw new SludiException(ErrorCodes.USER_NOT_FOUND);
            }

            AddressDto addressDto = mapToAddressDto(user);
            CredentialSubject credentialSubject = mapToCredentialSubject(user, addressDto);

            String credentialSubjectJson = objectMapper.writeValueAsString(credentialSubject);
            String credentialSubjectHash = cryptographyService.encryptData(credentialSubjectJson);

            List<SupportingDocumentResponseDto> supportingDocuments = mapSupportingDocuments(user, request);

            // Create Proof of Data
            ProofData proofData = digitalSignatureService.createProofData(
                    credentialSubjectJson,
                    user.getDidId(),
                    LocalDateTime.now().toString(),
                    ProofPurpose.CREDENTIAL_ISSUE.getValue()
            );

            ProofDataDto proofDataDto = ProofDataDto.builder()
                    .proofType(proofData.getProofType())
                    .creator(proofData.getCreator())
                    .created(proofData.getCreated())
                    .issuerDid(proofData.getIssuerDid())
                    .signatureValue(proofData.getSignatureValue())
                    .build();

            CredentialIssuanceRequestDto issuanceRequest = CredentialIssuanceRequestDto.builder()
                    .subjectDID(user.getDidId())
                    .issuerDID(proofDataDto.getIssuerDid())
                    .credentialType(request.getCredentialType())
                    .credentialSubjectHash(credentialSubjectHash)
                    .supportingDocuments(supportingDocuments)
                    .proofData(proofDataDto)
                    .build();

            log.info("Sending credential issuance request to Hyperledger for DID: {}", user.getDidId());

            VCBlockChainResult result = hyperledgerService.issueCredential(issuanceRequest);

            VerifiableCredential vc = VerifiableCredential.builder()
                    .id(result.getId())
                    .subjectDid(result.getSubjectDID())
                    .credentialType(result.getCredentialTypes())
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
                    .credentialType(result.getCredentialTypes())
                    .status(result.getStatus())
                    .message("Verifiable Credential issued successfully")
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
                    .credentialTypes(vcBlockChainResult.getCredentialTypes())
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

    private List<SupportingDocumentResponseDto> mapSupportingDocuments(CitizenUser user, IssueVCRequestDto request) {
        List<SupportingDocumentResponseDto> supportingDocuments = new ArrayList<>();

        if (request.getSupportingDocuments() != null && !request.getSupportingDocuments().isEmpty()) {
            for (SupportingDocumentRequestDto doc : request.getSupportingDocuments()) {
                String hash = storeFileToIPFS(user.getId(), request.getCredentialType(), doc);
                supportingDocuments.add(SupportingDocumentResponseDto.builder()
                        .name(doc.getName())
                        .fileType(doc.getType())
                        .ipfsCid(hash)
                        .build());
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

}
