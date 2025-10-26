package org.example.exception;

public enum ErrorCodes {
    // Authentication Errors (1000-1999)
    AUTH_FAILED("1000", "Authentication failed"),
    INVALID_CREDENTIALS("1001", "Invalid credentials provided"),
    BIOMETRIC_VERIFICATION_FAILED("1002", "Biometric verification failed"),
    USER_NOT_AUTHORIZED_TO_ACCESS_PROFILE("1003", "User not authorized to access this profile"),
    USER_INACTIVE("1004", "User is inactive"),
    BIOMETRIC_MISMATCH("1005", "Biometric data does not match"),
    USER_NOT_REGISTERED("1006", "User is not registered"),
    INVALID_AUTHRTIZATION_HEADER("1007", "Invalid authorization header provided"),
    UNAUTHORIZED("1008", "Unauthorized access"),
    UNAUTHORIZED_USER("1009", "Unauthorized user access"),


    // Data Processing Errors (2000-2999)
    ADDRESS_PARSE_ERROR("2000", "Failed to parse address data"),
    ADDRESS_CONVERSION_ERROR("2001", "Failed to convert address to JSON"),
    DEVICE_INFO_CONVERSION_ERROR("2002", "Failed to convert device info"),
    DOCUMENT_UPDATE_ERROR("2003", "Failed to update document references"),
    USER_EXISTS_WITH_NIC("2004", "User with this NIC already exists"),
    USER_EXISTS_WITH_EMAIL("2005", "User with this email already exists"),
    USER_REGISTRATION_FAILED("2006", "User registration failed"),
    USER_NOT_FOUND("2007", "User not found"),
    CANNOT_UPDATE_INACTIVE_USER("2008", "Cannot update inactive user"),
    USER_PROFILE_UPDATE_FAILED("2009", "User profile update failed"),
    FAILD_TO_RETRIEVE_USER_PROFILE("2010", "Failed to retrieve user profile"),
    USER_DEACTIVATION_FAILED("2011", "User deactivation failed"),
    STATISTICS_RETRIEVAL_FAILED("2012", "Failed to retrieve user statistics"),
    USER_EXISTS_WITH_USERORGANIZATIONID("2013","User with this user-organization-id exists"),
    TEMPLATE_NOT_FOUND("2014", "Template not found"),
    TEMPLATE_EXISTS_WITH_CODE("2015","Template is already exists"),
    DUPLICATE_ORGANIZATION("2016", "Organization with registration number already exists"),
    ORGANIZATION_REGISTRATION_FAILED("2017","Organization Registration failed"),



    // Storage Errors (3000-3999)
    IPFS_STORAGE_ERROR("3000", "Failed to store data in IPFS"),
    BIOMETRIC_RETRIEVAL_ERROR("3001", "Failed to retrieve biometric data"),
    DOCUMENT_STORAGE_ERROR("3002", "Failed to store documents"),
    BIOMETRIC_HASH_GENERATION_ERROR("3003", "Failed to generate biometric hash"),
    BLOCKCHAIN_REGISTRATION_FAILED("3004", "Failed to register user on blockchain"),
    CREDENTIAL_ISSUANCE_FAILED("3005", "Failed to issue credential on blockchain"),
    IPFS_INITIALIZATION_FAILED("3006", "Failed to initialize IPFS client"),
    FILE_READ_ERROR("3007", "Failed to read file from storage"),
    JSON_SERIALIZATION_FAILED("3008", "Failed to serialize and store JSON data"),
    JSON_DESERIALIZATION_FAILED("3009", "Failed to retrieve and deserialize JSON data"),
    BIOMETRIC_STORAGE_FAILED("3010", "Failed to store biometric data"),
    BIOMETRIC_ACCESS_DENIED("3011", "User ID mismatch for biometric data access"),
    DATA_INTEGRITY_FAILED("3012", "Biometric data checksum verification failed"),
    DOCUMENT_ACCESS_DENIED("3013", "User ID mismatch for document access"),
    DOCUMENT_RETRIEVAL_FAILED("3014", "Failed to retrieve document data"),
    IPFS_CONNECTION_FAILED("3015", "Failed to get IPFS node info"),
    IPFS_STORAGE_FAILED("3016", "IPFS returned empty result for file"),
    IPFS_FILE_NOT_FOUND("3017", "File not found or empty for hash"),
    IPFS_RETRIEVAL_FAILED("3018", "Failed to retrieve file from IPFS"),
    CHECKSUM_GENERATION_FAILED("3019", "Failed to generate checksum"),
    DID_NOT_FOUND("3020", "Failed to read DID document from blockchain"),
    DID_UPDATE_FAILED("3021", "Failed to update DID on blockchain"),
    DID_DEACTIVATION_FAILED("3022", "Failed to deactivate DID on blockchain"),
    CREDENTIAL_RETRIEVAL_FAILED("3023", "Failed to retrieve credential from blockchain"),
    CREDENTIAL_REVOCATION_FAILED("3024", "Failed to revoke credential on blockchain"),
    LEDGER_INITIALIZATION_FAILED("3025", "Failed to initialize blockchain ledger"),
    SYSTEM_STATS_FAILED("3026", "Failed to retrieve system statistics"),
    AUTH_LOG_RETRIEVAL_FAILED("3027", "Failed to retrieve authentication logs"),
    DID_RETRIEVAL_FAILED("3028", "Failed to retrieve DIDs document from blockchain"),

    // Validation Errors (4000-4999
    INVALID_INPUT("4000", "Invalid input provided"),
    MISSING_REQUIRED_FIELD("4001", "Required field is missing"),
    INVALID_FORMAT("4002", "Invalid document format. Only PDF and image files are allowed"),
    BIOMETRIC_INVALID("4003", "Biometric invalid"),
    INVALID_NIC("4004", "Invalid NIC format"),
    MISSING_BIOMETRIC_DATA("4005", "Missing biometric data"),
    MISSING_CONTACT_EMAIL("4006", "Missing contact email"),
    INVALID_TYPE("4007", "Invalid identifier type. Use: email, nic, or did"),
    ADMIN_ONLY_OPERATION("4008", "This operation is restricted to admin users only"),
    EMPTY_IMAGE("4009", "Image data cannot be empty"),
    FILE_TOO_LARGE("4010", "File size exceeds the maximum limit"),
    INVALID_FORMAT_IMAGE("4011", "Invalid image format. Only JPEG, JPG, and PNG are allowed"),

    // Security Errors (5000-5999)
    HASH_GENERATION_FAILED("5000", "Failed to generate hash"),
    ENCRYPTION_FAILED("5001", "Encryption failed"),
    UNAUTHORIZED_ACCESS("5002", "Unauthorized access attempt"),
    TOKEN_GENERATION_FAILED("5003", "Token generation failed"),
    TOKEN_EXPIRED("5004", "Token has expired"),
    TOKEN_INVALID("5005", "Invalid token provided"),
    INVALID_REFRESH_TOKEN("5006", "Invalid refresh token provided"),
    TOKEN_REFRESH_FAILED("5007", "Token refresh failed"),
    DECRYPTION_FAILED("5008", "Decryption failed"),
    SIGNATURE_GENERATION_FAILED("5009", "Signature generation failed"),
    ENCRYPTION_KEY_ERROR("5010", "Failed to process encryption key"),
    KEY_GENERATION_FAILED("5011", "Failed to generate key pair"),
    BIOMETRIC_ENCRYPTION_FAILED("5012", "Biometric data encryption failed"),
    BIOMETRIC_DECRYPTION_FAILED("5013", "Biometric data decryption failed"),;

    private final String code;
    private final String description;

    ErrorCodes(String code, String description) {
        this.code = code;
        this.description = description;
    }

    public String getCode() {
        return code;
    }

    public String getDescription() {
        return description;
    }
}