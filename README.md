# SLUDI-Backend

**SLUDI (Sri Lankan Unique Digital Identity)** is a comprehensive blockchain-based digital identity management system that provides secure, decentralized identity verification using Hyperledger Fabric, IPFS, and AI-powered biometric authentication.

![Java](https://img.shields.io/badge/Java-21-orange)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.4-brightgreen)
![Hyperledger Fabric](https://img.shields.io/badge/Hyperledger%20Fabric-1.8.0-blue)
![License](https://img.shields.io/badge/License-Apache%202.0-blue)

## 🌟 Features

### Core Capabilities
- **Decentralized Identity (DID)**: Blockchain-based identity creation and management
- **Biometric Authentication**: Fingerprint, face recognition, and signature verification
- **Verifiable Credentials**: Issue and verify government credentials (Identity, Driving License)
- **Digital Wallet**: Secure credential storage with cryptographic authentication
- **AI-Powered Security**: Deepfake detection and liveness checks
- **Privacy-Preserving**: Selective disclosure via Verifiable Presentations
- **Distributed Storage**: IPFS for encrypted biometric data
- **Multi-Organization Support**: Role-based access control for organizations

### Security Features
- ✅ Field-level AES-256 encryption for PII
- ✅ Dual JWT authentication (Citizen & Organization)
- ✅ Digital signatures (SHA256withECDSA)
- ✅ Hash-based indexing for privacy
- ✅ Immutable blockchain audit trail
- ✅ TLS/SSL encrypted communications

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Spring Boot Backend                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Controllers  │  │   Services   │  │ Repositories │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                 │                 │               │
│         └─────────────────┴─────────────────┘               │
└─────────────────┬───────────────────┬───────────────────────┘
                  │                   │
        ┌─────────┴─────────┐  ┌──────┴──────┐
        │  Hyperledger      │  │    IPFS     │
        │  Fabric Network   │  │   Storage   │
        │  (DID & VCs)      │  │ (Biometrics)│
        └───────────────────┘  └─────────────┘
                  │
        ┌─────────┴─────────┐
        │   PostgreSQL DB   │
        │  (User Metadata)  │
        └───────────────────┘
```

## 📋 Prerequisites

- **Java**: JDK 21 or higher
- **Docker**: 20.10+ and Docker Compose
- **Hyperledger Fabric**: Test network running
- **PostgreSQL**: 16+ (or use Docker)
- **IPFS**: Kubo node (or use Docker)
- **Redis**: Latest (or use Docker)
- **Gradle**: 6.5+ or Maven 3.6+

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/Tishan-001/SLUDI-Backend.git
cd SLUDI-Backend
```

### 2. Configure Environment Variables
Create a `.env` file or update `docker-compose.yml` with your configuration:

```bash
# Application
SERVER_PORT=5000
SPRING_BASE_URL=https://your-domain.com

# Database
SPRING_DATASOURCE_URL=jdbc:postgresql://postgres:5432/sluditest
SPRING_DATASOURCE_USERNAME=postgres
SPRING_DATASOURCE_PASSWORD=your_secure_password

# Redis
SPRING_REDIS_HOST=redis
SPRING_REDIS_PORT=6379
SPRING_REDIS_PASSWORD=your_redis_password

# IPFS
IPFS_API_HOST=ipfs
IPFS_API_PORT=5001
IPFS_GATEWAY_URL=http://ipfs:8080/ipfs/

# Hyperledger Fabric
FABRIC_MSP_ID=Org1MSP
FABRIC_CHANNEL_NAME=sludi-channel
FABRIC_CHAINCODE_NAME=sludiChaincode
FABRIC_PEER_ENDPOINT=peer0.org1.example.com:7051

# Security
JWT_SECRET_KEY=your_base64_encoded_secret_key
```

### 3. Start Infrastructure Services
```bash
# Start PostgreSQL, IPFS, and Redis
docker-compose up -d postgres ipfs redis
```

### 4. Build the Application

**Using Gradle:**
```bash
./gradlew clean build
```

**Using Maven:**
```bash
mvn clean install
```

### 5. Run the Application

**Using Gradle:**
```bash
./gradlew bootRun
```

**Using Maven:**
```bash
mvn spring-boot:run
```

**Using Docker:**
```bash
docker-compose up -d backend
```

The application will start on `http://localhost:5000`

## 📚 API Documentation

Once the application is running, access the interactive API documentation:

- **Swagger UI**: http://localhost:5000/swagger-ui.html
- **OpenAPI Spec**: http://localhost:5000/v3/api-docs

### Key API Endpoints

#### Citizen User Management
```http
POST   /api/citizen-user/register              # Register new citizen
GET    /api/citizen-user/profile?id={uuid}     # Get user profile
PUT    /api/citizen-user/{id}/profile          # Update profile
POST   /api/citizen-user/{id}/profile-photo    # Upload profile photo
POST   /api/citizen-user/save-biometric        # Save biometric data
```

#### DID Management
```http
POST   /api/did/register                       # Create new DID
GET    /api/did/{didId}                        # Retrieve DID document
PUT    /api/did/{didId}                        # Update DID document
DELETE /api/did/{didId}                        # Deactivate DID
```

#### Verifiable Credentials
```http
POST   /api/vc/issue/identity                  # Issue identity credential
POST   /api/vc/issue/driving-license           # Issue driving license
GET    /api/vc/{credentialId}                  # Retrieve credential
POST   /api/vc/verify                          # Verify credential
```

#### Digital Wallet
```http
POST   /api/wallet/initiate                    # Initiate wallet creation
POST   /api/wallet/create                      # Create wallet
POST   /api/wallet/challenge                   # Generate auth challenge
POST   /api/wallet/verify-challenge            # Verify signed challenge
GET    /api/wallet/retrieve?did={did}          # Retrieve wallet data
```

#### Deepfake Detection
```http
POST   /api/deepfake/detect                    # Detect image deepfakes
POST   /api/deepfake/detect-video              # Detect video deepfakes
POST   /api/deepfake/quick-check               # Quick liveness check
```

#### Blockchain
```http
GET    /api/blockchain/health                  # Check blockchain health
GET    /api/blockchain/network-info            # Get network details
GET    /api/blockchain/stats                   # System statistics
```

## 🔧 Configuration

### Application Properties

Key configuration options in `application.properties`:

```properties
# Server
server.port=5000

# Fabric Configuration
fabric.msp-id=Org1MSP
fabric.channel-name=sludi-channel
fabric.chaincode-name=sludiChaincode
fabric.crypto-path=/path/to/fabric/crypto
fabric.peer-endpoint=localhost:7051

# IPFS Settings
ipfs.api.host=localhost
ipfs.api.port=5001
sludi.ipfs.encryption.enabled=true
sludi.ipfs.pin.enabled=true
sludi.ipfs.timeout.seconds=30
sludi.ipfs.retry.attempts=3

# JWT Settings
security.jwt.access.expiration-time=900000      # 15 minutes
security.jwt.refresh.expiration-time=604800000  # 7 days

# File Upload
spring.servlet.multipart.max-file-size=5MB
spring.servlet.multipart.max-request-size=5MB

# Database Pool
spring.datasource.hikari.maximum-pool-size=10
spring.datasource.hikari.minimum-idle=2
```

## 🔐 Security

### Authentication Flow

#### Citizen Authentication
1. **Registration**: User registers with biometrics → DID created on blockchain
2. **Wallet Setup**: OTP verification → Wallet created with public key
3. **Login**: Challenge-response authentication with digital signature
4. **Access**: JWT token issued for API access

#### Organization Authentication
1. **Login**: Credentials-based authentication
2. **Authorization**: Role-based access control with permission templates
3. **Access**: JWT token with organization-specific claims

### Data Encryption

- **At Rest**: AES-256 encryption for all PII in PostgreSQL
- **In Transit**: TLS/SSL for all communications
- **IPFS Storage**: Encrypted before upload with integrity hashes
- **Indexing**: SHA-256 hashes for unique constraints (privacy-preserving)

## 🐳 Docker Deployment

### Full Stack Deployment
```bash
docker-compose up -d
```

This starts:
- **PostgreSQL** (port 5432)
- **IPFS** (ports 4001, 5001, 8080)
- **Redis** (port 6379)
- **SLUDI Backend** (port 5000)

### Individual Services
```bash
# Start only database
docker-compose up -d postgres

# Start only IPFS
docker-compose up -d ipfs

# View logs
docker-compose logs -f backend
```

## 🔄 Key Workflows

### 1. Citizen Registration
```
User Submits Form → Validate Data → Deepfake Detection → 
Store Biometrics (IPFS) → Generate DID → Sign DID → 
Submit to Blockchain → Save to PostgreSQL → Send Verification Email
```

### 2. Driving License Issuance
```
Officer Generates QR → Citizen Scans → Wallet Retrieves Request → 
Citizen Approves → Wallet Submits VP → System Verifies → 
Officer Reviews → Issues VC → Store on Blockchain → Add to Wallet
```

### 3. Wallet Authentication
```
Request Challenge → Generate Nonce → Wallet Signs → 
Verify Signature → Issue JWT Token
```

## 📊 Database Schema

### Core Entities
- **CitizenUser**: User profiles with encrypted PII
- **DIDDocument**: Blockchain-based identity documents
- **VerifiableCredential**: Government-issued credentials
- **Wallet**: Digital wallet for credential storage
- **Organization**: Multi-org support with RBAC
- **Appointment**: Appointment scheduling system
- **IPFSContent**: Metadata for IPFS-stored files

## 🧪 Testing

```bash
# Run all tests
./gradlew test

# Run with coverage
./gradlew test jacocoTestReport

# Run specific test class
./gradlew test --tests "CitizenUserServiceTest"
```

## 📦 Dependencies

### Core Libraries
- **Spring Boot**: 3.5.4
- **Hyperledger Fabric Gateway**: 1.8.0
- **IPFS Java API**: 1.3.3
- **JWT (JJWT)**: 0.11.5
- **BouncyCastle**: 1.78
- **PostgreSQL Driver**: 42.7.3
- **Redis**: Spring Data Redis
- **Lombok**: 1.18.34
- **SpringDoc OpenAPI**: 2.8.0
- **ZXing (QR Codes)**: 3.5.3

## 🛠️ Development

### Project Structure
```
src/main/java/org/example/
├── config/              # Configuration classes
├── controller/          # REST API controllers (10)
├── dto/                 # Data Transfer Objects (97+)
├── entity/              # JPA entities (25)
├── exception/           # Custom exceptions
├── integration/         # External integrations (IPFS, Fabric, AI)
├── repository/          # Data repositories (17)
├── security/            # Security filters & configs
├── service/             # Business logic (16 services)
└── utils/               # Utility classes
```

### Code Style
- Follow Java naming conventions
- Use Lombok for boilerplate reduction
- Document public APIs with JavaDoc
- Write unit tests for services

## 🚨 Troubleshooting

### Common Issues

**1. Blockchain Connection Failed**
```bash
# Check Fabric network is running
docker ps | grep hyperledger

# Verify peer endpoint
curl -k https://peer0.org1.example.com:7051
```

**2. IPFS Connection Error**
```bash
# Check IPFS daemon
docker logs ipfs_node

# Test IPFS API
curl http://localhost:5001/api/v0/version
```

**3. Database Connection Issues**
```bash
# Check PostgreSQL
docker logs postgres-container

# Test connection
psql -h localhost -U postgres -d sluditest
```

## 📈 Performance Optimization

- **Connection Pooling**: HikariCP with optimized settings
- **Redis Caching**: Cache frequently accessed data
- **Async Processing**: Use `@Async` for heavy operations
- **IPFS Pinning**: Ensure data persistence
- **Database Indexing**: Hash-based indexes for fast lookups

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Contribution Guidelines
- Write meaningful commit messages
- Add tests for new features
- Update documentation
- Follow existing code style
- Ensure all tests pass

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Hyperledger Fabric** - Blockchain framework
- **IPFS** - Distributed storage
- **Spring Framework** - Application framework
- **BouncyCastle** - Cryptography library

## 📞 Support

For issues and questions:
- **Email**: infosludi@gmail.com
- **Issues**: [GitHub Issues](https://github.com/Tishan-001/SLUDI-Backend/issues)

## 🗺️ Roadmap

- [ ] Multi-language support
- [ ] Mobile SDK for wallet integration
- [ ] Advanced analytics dashboard
- [ ] Biometric template matching
- [ ] Cross-chain interoperability
- [ ] Zero-knowledge proof integration
- [ ] Decentralized key recovery

---

**Built with ❤️ for secure digital identity management**
