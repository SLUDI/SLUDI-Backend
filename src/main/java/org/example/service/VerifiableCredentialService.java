package org.example.service;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.logging.Logger;

@Service
@Transactional
public class VerifiableCredentialService {

    private static final Logger LOGGER = Logger.getLogger(VerifiableCredentialService.class.getName());

    @Autowired
    private VerifiableCredentialRepository verifiableCredentialRepository;

    @Autowired
    private CitizenUserRepository userRepository;

    @Autowired
    private IPFSContentRepository ipfsContentRepository;

    @Autowired
    private HyperledgerService hyperledgerService;

    @Autowired
    private CryptographyService cryptographyService;

    @Autowired
    private DigitalSignatureService digitalSignatureService;

    @Autowired
    private IPFSIntegration ipfsIntegration;

    private final ObjectMapper objectMapper = new ObjectMapper();

    public VCIssuedResponseDto issueVC(IssueVCRequestDto request) {
        LOGGER.info("Issuing identity VC for DID: " + request.getDid()
                + ", CredentialType: " + request.getCredentialType());

        try {
            CitizenUser user = userRepository.findByEmailOrNicOrDidId(null, null, request.getDid());
            if (user == null) {
                LOGGER.warning("User not found for DID: " + request.getDid());
                throw new SludiException(ErrorCodes.USER_NOT_FOUND);
            }

            AddressDto addressDto = mapToAddressDto(user);
            CredentialSubject credentialSubject = mapToCredentialSubject(user, addressDto);

            String credentialSubjectJson = objectMapper.writeValueAsString(credentialSubject);
            String credentialSubjectHash = cryptographyService.encryptData(credentialSubjectJson);

            List<SupportingDocumentDto> supportingDocuments = mapSupportingDocuments(user, request);

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

            LOGGER.info("Sending credential issuance request to Hyperledger for DID: " + user.getDidId());

            VCBlockChainResult result = hyperledgerService.issueCredential(issuanceRequest);

            VerifiableCredential vc = VerifiableCredential.builder()
                    .id(result.getId())
                    .subjectDid(result.getSubjectDID())
                    .credentialType(result.getCredentialTypes())
                    .issuerDid(result.getIssuer())
                    .issuanceDate(result.getIssuanceDate())
                    .expirationDate(result.getExpirationDate())
                    .status(result.getStatus())
                    .blockchainTxId(result.getBlockchainTxId())
                    .blockNumber(result.getBlockNumber())
                    .credentialSubjectHash(result.getCredentialSubjectHash())
                    .build();

            verifiableCredentialRepository.save(vc);

            LOGGER.info("VC issued successfully. CredentialId: " + result.getId()
                    + ", TxId: " + result.getBlockchainTxId());

            return VCIssuedResponseDto.builder()
                    .credentialId(result.getId())
                    .subjectDID(result.getSubjectDID())
                    .credentialType(result.getCredentialTypes())
                    .status(result.getStatus())
                    .message("Verifiable Credential issued successfully")
                    .blockchainTxId(result.getBlockchainTxId())
                    .build();
        } catch (SludiException e) {
            LOGGER.warning("Business error during VC issuance: " + e.getMessage());
            throw e;
        } catch (Exception e) {
            LOGGER.severe("Unexpected error while issuing VC for DID: " + request.getDid()
                    + ". Error: " + e.getMessage());
            throw new SludiException(ErrorCodes.FAILED_TO_ISSUE_IDENTITY_VC, e);
        }
    }

    /**
     * Get Identity Verifiable Credential (IVC) for a user
     * This method retrieves the IVC for a user based on their DID ID.
     */
    public VerifiableCredentialDto getVerifiableCredential(String credentialId) {
        LOGGER.info("Fetching Verifiable Credential for ID: " + credentialId);

        try {
            if (credentialId == null || credentialId.trim().isEmpty()) {
                LOGGER.warning("Attempt to fetch credential with null/empty ID.");
                throw new SludiException(ErrorCodes.CREDENTIAL_NOT_FOUND, "Credential ID cannot be null or empty");
            }

            LOGGER.info("Querying blockchain for credentialId: " + credentialId);
            VCBlockChainResult vcBlockChainResult = hyperledgerService.readCredential(credentialId);

            if (vcBlockChainResult == null) {
                LOGGER.warning("No credential found on blockchain for ID: " + credentialId);
                throw new SludiException(ErrorCodes.CREDENTIAL_NOT_FOUND, "No credential found for ID: " + credentialId);
            }

            LOGGER.info("Decrypting credential subject for credentialId: " + credentialId);
            String credentialSubjectJson = cryptographyService.decryptData(vcBlockChainResult.getCredentialSubjectHash());

            CredentialSubject credentialSubject;
            try {
                credentialSubject = objectMapper.readValue(credentialSubjectJson, CredentialSubject.class);
            } catch (Exception parseEx) {
                LOGGER.severe("Failed to parse CredentialSubject JSON for credentialId: "
                        + credentialId + ". Error: " + parseEx.getMessage());
                throw new SludiException(ErrorCodes.FAILED_TO_RETRIEVE_IDENTITY_VC, "Invalid credential subject format", parseEx);
            }

            LOGGER.info("Successfully retrieved Verifiable Credential for ID: " + credentialId);



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
            LOGGER.warning("Business exception while fetching VC for credentialId: "
                    + credentialId + ". Error: " + e.getMessage());
            throw e;
        } catch (Exception e) {
            LOGGER.severe("Unexpected error while fetching VC for credentialId: "
                    + credentialId + ". Error: " + e.getMessage());
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
                .state(user.getAddress().getState())
                .country(user.getAddress().getCountry())
                .build();
    }

    private CredentialSubject mapToCredentialSubject(CitizenUser user, AddressDto addressDto) {
        return CredentialSubject.builder()
                .id(user.getDidId())
                .fullName(user.getFullName())
                .nic(user.getNic())
                .dateOfBirth(user.getDateOfBirth())
                .citizenship(user.getCitizenship())
                .gender(user.getGender())
                .nationality(user.getNationality())
                .address(addressDto)
                .build();
    }

    private List<SupportingDocumentDto> mapSupportingDocuments(CitizenUser user, IssueVCRequestDto request) {
        List<SupportingDocumentDto> supportingDocuments = new ArrayList<>();

        if (request.getSupportingDocuments() != null && !request.getSupportingDocuments().isEmpty()) {
            for (SupportingDocument doc : request.getSupportingDocuments()) {
                String hash = storeFileToIPFS(user.getId(), request.getCredentialType(), doc);
                supportingDocuments.add(SupportingDocumentDto.builder()
                        .name(doc.getName())
                        .fileType(doc.getType())
                        .ipfsCid(hash)
                        .build());
            }
            LOGGER.info("Stored " + supportingDocuments.size() + " supporting documents in IPFS.");
        }

        return supportingDocuments;
    }

    /**
     * Uploads a document to IPFS and returns the CID/hash
     */
    private String storeFileToIPFS(UUID userId, String credentialType, SupportingDocument doc) {
        try {
            String path = String.format("%s/%s/%s", userId, credentialType, doc.getName());
            byte[] fileBytes = doc.getFile().getBytes();
            return ipfsIntegration.storeFile(path, fileBytes);
        } catch (Exception e) {
            throw new RuntimeException("Failed to store document on IPFS: " + e.getMessage(), e);
        }
    }

}
