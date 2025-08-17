package org.example.service;

import org.example.entity.DIDDocument;
import org.example.entity.PublicKey;
import org.example.entity.Services;
import org.example.entity.VerifiableCredential;
import org.example.security.CryptographyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;

@Service
public class DataIntegrityService {

    @Autowired
    private HyperledgerService hyperledgerService;

    @Autowired
    private CryptographyService cryptographyService;

    /**
     * Validates the integrity of a DID Document
     * @param didDocument
     * @return true if the DID Document is valid and matches the blockchain record, false otherwise
     */
    public boolean verifyDidDocumentIntegrity(DIDDocument didDocument) {

        // Check the blockchain record
        DIDDocument blockchainDidDocument = hyperledgerService.getDIDDocument(didDocument.getId());
        if (blockchainDidDocument == null) {
            return false; // DID Document not found on the blockchain
        }

        // Compare the local and blockchain records
        return Objects.equals(didDocument.getId(), blockchainDidDocument.getId())
                && Objects.equals(didDocument.getDidVersion(), blockchainDidDocument.getDidVersion())
                && comparePublicKeys(didDocument.getPublicKey(), blockchainDidDocument.getPublicKey())
                && compareAuthentication(didDocument.getAuthentication(), blockchainDidDocument.getAuthentication())
                && compareServices(didDocument.getServices(), blockchainDidDocument.getServices())
                && Objects.equals(didDocument.getStatus(), blockchainDidDocument.getStatus())
                && Objects.equals(didDocument.getProof(), blockchainDidDocument.getProof());
    }

    /**
     * Validates the integrity of a Verifiable Credential
     * @param credential
     * @return true if the credential is valid and matches the blockchain record, false otherwise
     */
    public boolean verifyCredentialIntegrity(VerifiableCredential credential) {

        // Check the blockchain record
        VerifiableCredential blockchainCredential = hyperledgerService.readCredential(credential.getId());
        if (blockchainCredential == null) {
            return false; // Credential not found on the blockchain
        }

        // Compare the local and blockchain records
        return Objects.equals(credential.getId(), blockchainCredential.getId())
                && compareContext(credential.getContext(), blockchainCredential.getContext())
                && compareCredentialTypes(credential.getCredentialTypes(), blockchainCredential.getCredentialTypes())
                && Objects.equals(credential.getIssuer(), blockchainCredential.getIssuer())
                && Objects.equals(credential.getIssuanceDate(), blockchainCredential.getIssuanceDate())
                && Objects.equals(credential.getExpirationDate(), blockchainCredential.getExpirationDate())
                && Objects.equals(credential.getCredentialSubject(), blockchainCredential.getCredentialSubject())
                && Objects.equals(credential.getStatus(), blockchainCredential.getStatus())
                && Objects.equals(credential.getProof(), blockchainCredential.getProof());
    }

    private boolean comparePublicKeys(List<PublicKey> localKeys, List<PublicKey> blockchainKeys) {
        if (localKeys == null) return blockchainKeys == null;
        if (blockchainKeys == null || localKeys.size() != blockchainKeys.size()) return false;

        for (PublicKey localKey : localKeys) {
            boolean match = blockchainKeys.stream().anyMatch(bKey ->
                    Objects.equals(localKey.getId(), bKey.getId()) &&
                            Objects.equals(localKey.getType(), bKey.getType()) &&
                            Objects.equals(localKey.getController(), bKey.getController()) &&
                            Objects.equals(localKey.getPublicKeyBase58(), bKey.getPublicKeyBase58())
            );
            if (!match) return false;
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

    private boolean compareServices(List<Services> services, List<Services> services1) {
        if (services == null) return services1 == null;
        if (services1 == null || services.size() != services1.size()) return false;

        for (Services service : services) {
            boolean match = services1.stream().anyMatch(s ->
                    Objects.equals(service.getId(), s.getId()) &&
                            Objects.equals(service.getType(), s.getType()) &&
                            Objects.equals(service.getServiceEndpoint(), s.getServiceEndpoint())
            );
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

}
