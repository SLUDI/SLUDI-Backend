package org.example.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.dto.*;
import org.example.entity.CitizenUser;
import org.example.entity.VerifiableCredential;
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
import org.springframework.web.multipart.MultipartFile;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
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
    private IPFSIntegration ipfsIntegration;

    private final ObjectMapper objectMapper = new ObjectMapper();

    public VCIssuedResponseDto issueIdentityVC(IssueIdentityVCRequestDto request) {
        try {
            CitizenUser user = userRepository.findByEmailOrNicOrDidId(null, null, request.getDid())
                    .orElseThrow(() -> new SludiException(ErrorCodes.USER_NOT_FOUND));

            AddressDto addressDto = AddressDto.builder()
                    .street(user.getAddress().getStreet())
                    .city(user.getAddress().getCity())
                    .district(user.getAddress().getDistrict())
                    .postalCode(user.getAddress().getPostalCode())
                    .divisionalSecretariat(user.getAddress().getDivisionalSecretariat())
                    .gramaNiladhariDivision(user.getAddress().getGramaNiladhariDivision())
                    .state(user.getAddress().getState())
                    .country(user.getAddress().getCountry())
                    .build();

            CredentialSubject credentialSubject = CredentialSubject.builder()
                    .id(user.getDidId())
                    .fullName(user.getFullName())
                    .nic(user.getNic())
                    .dateOfBirth(user.getNic())
                    .citizenship(user.getCitizenship())
                    .gender(user.getCitizenship())
                    .nationality(user.getNationality())
                    .address(addressDto)
                    .build();

            String credentialSubjectJson = objectMapper.writeValueAsString(credentialSubject);

            String credentialSubjectHash = CryptographyService.encryptData(credentialSubjectJson);

            // Handle supporting documents asynchronously (IPFS)
            List<SupportingDocumentDto> supportingDocuments = new ArrayList<>();
            if (request.getSupportingDocuments() != null) {
                for (SupportingDocument doc : request.getSupportingDocuments()) {
                    String hash = storeFileToIPFS(user.getId(), request.getCredentialType(), doc);
                    supportingDocuments.add(SupportingDocumentDto.builder()
                                    .name(doc.getName())
                                    .fileType(doc.getType())
                                    .ipfsCid(hash)
                                    .build());
                }
            }

            // Build Credential Issuance Request DTO for chaincode
            CredentialIssuanceRequestDto issuanceRequest = CredentialIssuanceRequestDto.builder()
                    .subjectDID(user.getDidId())
                    .credentialType(request.getCredentialType())
                    .credentialSubjectHash(credentialSubjectHash)
                    .supportingDocuments(supportingDocuments)
                    .build();


            VCBlockChainResult result = hyperledgerService.issueCredential(issuanceRequest);

            VerifiableCredential vc = VerifiableCredential.builder()
                    .id(result.getId())
                    .subjectDid(result.getSubjectDID())
                    .credentialType(result.getCredentialTypes())
                    .issuerDid(result.getIssuer())
                    .build();
        }
        catch (Exception e) {
            LOGGER.severe("Failed to issue identity VC: " + e.getMessage());
            throw new SludiException(ErrorCodes.FAILED_TO_ISSUE_IDENTITY_VC, e);
        }
    }

    /**
     * Get Identity Verifiable Credential (IVC) for a user
     * This method retrieves the IVC for a user based on their DID ID.
     */
    public VerifiableCredentialDto getVerifiableCredential(String credentialId) {
        try {
            // Check if the Credential exists
            if (credentialId == null || credentialId.isEmpty()) {
                throw new SludiException(ErrorCodes.CREDENTIAL_NOT_FOUND, "Credential ID cannot be null or empty");
            }



        } catch (Exception e) {
            throw new SludiException(ErrorCodes.FAILED_TO_RETRIEVE_IDENTITY_VC, e.getMessage(), e);
        }
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
