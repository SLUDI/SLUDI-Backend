package org.example.enums;

/**
 * Enum representing valid proof purposes within the Sludi system.
 * These values describe the context for which a signature is created.
 */
public enum ProofPurpose {
    DID_CREATION("DIDCreation"),
    CREDENTIAL_ISSUE("CredentialIssue"),
    CREDENTIAL_VERIFICATION("CredentialVerification"),
    REVOCATION("Revocation");

    private final String value;

    ProofPurpose(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    @Override
    public String toString() {
        return value;
    }
}
