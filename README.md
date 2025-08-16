# SLUDI-Backend

SLUDI (Sri Lankan Unique Digital Identity) Backend is a Spring Boot application that provides secure digital identity management using blockchain technology and biometric verification.

## Features

- User registration with biometric data (fingerprint, face image, signature)
- Secure storage using IPFS and Hyperledger Fabric blockchain
- AI-powered deepfake detection and liveness checks
- Biometric authentication
- DID (Decentralized Identifier) management
- Profile management with KYC status tracking

## Prerequisites

- Java 21
- PostgreSQL 
- Hyperledger Fabric network
- IPFS node
- Maven or Gradle

## Configuration

Configure the application in [application.properties](src/main/resources/application.properties):

```properties
server.port=5000
spring.application.name=sludi

#Properties of Fabric
fabric.msp-id=Org1MSP
fabric.channel-name=sludi-channel
fabric.chaincode-name=sludi-Chaincode
fabric.crypto-path=/home/tsm/go/src/github.com/Tishan-001/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com
fabric.peer-endpoint=localhost:7051
fabric.override-auth=peer0.org1.example.com
sludi.issuer-did=did:sludi:government789
fabric.wallet.path=/home/tsm/go/src/github.com/Tishan-001/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/msp/keystore

#Properties of postgresql
spring.datasource.url = jdbc:postgresql://localhost:5432/sluditest
spring.datasource.username = postgres
spring.datasource.password = mysecretpassword
spring.datasource.driver-class-name = org.postgresql.Driver
spring.jpa.hibernate.ddl-auto = update
spring.jpa.properties.hibernate.dialect = org.hibernate.dialect.PostgreSQLDialect

#Properties of IPFS
ipfs.api.host=localhost
ipfs.api.port=5001
ipfs.gateway.url=http://localhost:8080/ipfs/
sludi.ipfs.encryption.enabled=true
sludi.ipfs.pin.enabled=true
sludi.ipfs.timeout.seconds=30
sludi.ipfs.retry.attempts=3

# Properties of JWT
sludi.jwt.secret=mysecretkey1234567890
sludi.jwt.access-token-expiration=3600
sludi.jwt.refresh-token-expiration=2592000

# Encryption and Decryption Key
sludi.encryption.key=myencryptionkey1234567890

# Properties for file upload
spring.servlet.multipart.enabled=true
spring.servlet.multipart.max-file-size=5MB
spring.servlet.multipart.max-request-size=5MB
```

## Building the Project

Using Gradle:
```bash
./gradlew build
```

Using Maven:
```bash
mvn clean install
```

## Running the Application

Using Gradle:
```bash
./gradlew bootRun
```

Using Maven:
```bash
mvn spring-boot:run
```

## Running IPFS and PostgreSQL containers
```bash
docker-compose up -d
```
## API Endpoints

### User Registration
```http
POST /api/users/register
```

### User Authentication
```http
POST /api/users/authenticate
```

### Profile Management
```http
GET /api/users/{userId}/profile
PUT /api/users/{userId}/profile
```

## Security Features

- Biometric data verification
- AI-powered deepfake detection
- Blockchain-based identity verification
- Encrypted data storage
- Secure key management

## Architecture

- Spring Boot backend
- PostgreSQL for user data
- IPFS for biometric data storage
- Hyperledger Fabric for DID management
- AI services for biometric verification

## Dependencies

- Spring Boot 3.5.4
- Hyperledger Fabric Gateway 1.8.0
- gRPC 1.67.1
- Google Protocol Buffers 4.28.2
- GSON 2.11.0

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.
