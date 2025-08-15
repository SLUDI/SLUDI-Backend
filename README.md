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

# Fabric Configuration
fabric.msp-id=Org1MSP
fabric.channel-name=channel1
fabric.chaincode-name=identity
fabric.crypto-path=/path/to/crypto/materials
fabric.peer-endpoint=localhost:7051
fabric.override-auth=peer0.org1.example.com

# PostgreSQL Configuration
spring.datasource.url=jdbc:postgresql://localhost:5432/sluidtest
spring.datasource.username=postgres
spring.datasource.password=mysecretpassword
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