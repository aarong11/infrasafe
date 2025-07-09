# InfraSafe Smart Contract System

## License

This project is dual-licensed:

- 🪪 **[GNU GPLv3](LICENSE-GPL)** for open source use
- 💼 **[Commercial License](LICENSE-COMMERCIAL)** for proprietary use

To obtain a commercial license, contact: [contact@infrasim.org](mailto:contact@infrasim.org)


![InfraSafe Logo](https://img.shields.io/badge/InfraSafe-v1.0.0-blue)
![Solidity](https://img.shields.io/badge/Solidity-0.8.22-green)
![License](https://img.shields.io/badge/license-MIT-blue)
![Tests](https://img.shields.io/badge/tests-passing-brightgreen)

## 🎯 Overview

**InfraSafe** is a modern, upgradeable smart contract multisig wallet system built on Ethereum. It combines the battle-tested security principles of Gnosis Safe with modern Solidity patterns, offering enhanced functionality through a modular architecture. The system is designed for infrastructure teams, DeFi protocols, and organizations requiring secure, transparent, and flexible multi-signature wallet management.

### 🔑 Key Features

- **🛡️ Modern Multisig Security**: Configurable threshold-based transaction execution
- **🔄 Upgradeable Architecture**: UUPS (Universal Upgradeable Proxy Standard) implementation
- **👥 Role-Based Access Control**: Granular permissions for signers, admins, and trusted agents
- **🔗 Modular Extensions**: Pluggable fallback handlers for custom functionality
- **🔒 ERC-1271 Compatible**: Standard signature validation for smart contract wallets
- **⚡ Gas Optimized**: Efficient bytecode with OpenZeppelin optimizations
- **🧪 Thoroughly Tested**: Comprehensive test suite with >95% coverage
- **🌐 REST API**: Built-in metadata server for easy integration
- **🔐 WebAuthn Authentication**: Passwordless biometric authentication server

## 🏗️ Architecture

### Core Components

#### 1. **InfraSafe.sol** - Main Multisig Contract
The primary contract implementing the multisig wallet functionality with upgradeable capabilities.

**Key Features:**
- **Threshold-based execution**: Configurable number of required signatures
- **Nonce-based replay protection**: Prevents duplicate transaction execution
- **Role-based access**: Separate roles for signers, admins, and trusted agents
- **Emergency recovery**: Token recovery and fallback mechanisms
- **Event logging**: Comprehensive transaction and state change events

**Roles:**
- `DEFAULT_ADMIN_ROLE`: Can manage signers, threshold, and contract upgrades
- `SAFE_SIGNER_ROLE`: Can co-sign and execute transactions
- `TRUSTED_AGENT_ROLE`: Reserved for AI agent integrations (future enhancement)

#### 2. **FallbackHandler.sol** - Extension System
Enables pluggable functionality without requiring contract upgrades.

**Capabilities:**
- **Dynamic function routing**: Map function selectors to handler contracts
- **Pre/post execution hooks**: Monitor and log extension usage
- **Reentrancy protection**: Secure delegation to external handlers
- **Emergency controls**: Owner-controlled handler management

### 🔧 Technical Stack

- **Smart Contracts**: Solidity 0.8.22
- **Framework**: Hardhat with TypeScript
- **Upgrades**: OpenZeppelin Upgrades (UUPS pattern)
- **Testing**: Chai, Ethers.js v6, Jest, Playwright
- **Type Generation**: TypeChain
- **Backend**: Express.js REST API server
- **WebAuthn**: SimpleWebAuthn server for biometric authentication
- **Build System**: TypeScript compilation with source maps and declarations
- **Networks**: Ethereum, Sepolia testnet, local development

## 🚀 Quick Start

### Prerequisites

- Node.js 18+ and npm/yarn
- Git
- (Optional) Docker for containerized deployment

### 1. Clone and Install

```bash
git clone <repository-url>
cd infrasafe
yarn install
```

### 2. Environment Setup

Create a `.env` file:

```bash
# Network Configuration
SEPOLIA_RPC_URL=https://ethereum-sepolia.publicnode.com
BLOCKCHAIN_PRIVATE_KEY=your_private_key_here

# API Keys
ETHERSCAN_API_KEY=your_etherscan_api_key

# Server Configuration
ABI_SERVER_PORT=5656

# Development
REPORT_GAS=true
```

### 3. Compile Contracts

```bash
yarn compile
```

### 4. Run Tests

```bash
yarn test
```

### 5. Deploy Locally

```bash
# Start local Hardhat node
yarn node

# In another terminal, deploy contracts
yarn deploy

# Start the ABI metadata server
yarn serve
```

### 6. All-in-One Development

```bash
# Compile, deploy, and start main server
yarn start

# Start both InfraSafe and WebAuthn servers
yarn start:all
```

### 7. WebAuthn Authentication Server

```bash
# Development mode with auto-reload
yarn webauthn-server:dev

# Production build and start
yarn webauthn-server:start

# Build only
yarn webauthn-server:build
```

The WebAuthn server provides passwordless authentication at `http://localhost:3001`.

### 8. Development Help

```bash
# Show all available commands
yarn help
```

## 📖 Usage Guide

### Basic Multisig Operations

#### 1. Initialize a New Safe

```typescript
const signers = [
  "0x1234...5678",  // Signer 1
  "0xabcd...efgh",  // Signer 2
  "0x9876...5432"   // Signer 3
];
const threshold = 2; // Require 2 out of 3 signatures
const admin = "0xadmin...address";

await infraSafe.initialize(signers, threshold, admin);
```

#### 2. Execute a Transaction

```typescript
// Transaction details
const to = "0xrecipient...address";
const value = ethers.parseEther("1.0"); // 1 ETH
const data = "0x"; // Empty data for simple transfer
const nonce = await infraSafe.nonce();

// Generate transaction hash
const txHash = await infraSafe.getTransactionHash(to, value, data, nonce);

// Sign by required signers
const signature1 = await signer1.signMessage(ethers.getBytes(txHash));
const signature2 = await signer2.signMessage(ethers.getBytes(txHash));

// Execute transaction
await infraSafe.executeTransaction(
  to,
  value,
  data,
  [signature1, signature2]
);
```

#### 3. Manage Signers

```typescript
// Add a new signer (admin only)
await infraSafe.connect(admin).addSigner("0xnew...signer");

// Remove a signer (admin only)
await infraSafe.connect(admin).removeSigner("0xold...signer");

// Change threshold (admin only)
await infraSafe.connect(admin).changeThreshold(3);
```

### Advanced Features

#### 1. Fallback Handler Extensions

```typescript
// Deploy custom handler
const customHandler = await CustomHandler.deploy();

// Register handler for specific function selector
const selector = "0x12345678"; // First 4 bytes of function signature
await fallbackHandler.setHandler(selector, customHandler.address);

// Set fallback handler in InfraSafe
await infraSafe.setFallbackHandler(fallbackHandler.address);
```

#### 2. ERC-1271 Signature Validation

```typescript
// Validate a signature against the multisig
const messageHash = ethers.keccak256(ethers.toUtf8Bytes("Hello World"));
const signature = await signer.signMessage(ethers.getBytes(messageHash));

const isValid = await infraSafe.isValidSignature(messageHash, signature);
// Returns 0x1626ba7e if valid, 0xffffffff if invalid
```

#### 3. Emergency Token Recovery

```typescript
// Recover stuck ERC-20 tokens (admin only)
await infraSafe.connect(admin).emergencyTokenRecovery(
  tokenAddress,
  recipientAddress,
  amount
);
```

## 🌐 REST API Reference

The InfraSafe system includes a built-in REST API server for easy integration.

### Base URL
```
http://localhost:5656
```

### Endpoints

#### Health Check
```http
GET /health
```
Response:
```json
{
  "status": "healthy",
  "timestamp": "2025-07-09T10:30:00.000Z",
  "contractsLoaded": 2,
  "version": "1.0.0"
}
```

#### All Contracts
```http
GET /contracts
```
Response:
```json
{
  "InfraSafe": {
    "address": "0x1234...5678",
    "abi": [...],
    "signatures": [...],
    "implementationAddress": "0xabcd...efgh",
    "proxyAdminAddress": "0x9876...5432"
  },
  "FallbackHandler": {
    "address": "0xfedc...ba98",
    "abi": [...],
    "signatures": [...]
  }
}
```

#### Specific Contract
```http
GET /contracts/InfraSafe
```

#### Contract ABI
```http
GET /contracts/InfraSafe/abi
```

#### Function Signatures
```http
GET /contracts/InfraSafe/signatures
```

#### Contract Addresses
```http
GET /addresses
```

#### Reload Deployment Data
```http
POST /reload
```

## 🧪 Testing

### Smart Contract Tests

```bash
# Run all smart contract tests
yarn test

# Test coverage
yarn test:coverage

# Gas reporting
REPORT_GAS=true yarn test
```

### WebAuthn Authentication Tests

```bash
# Run WebAuthn E2E tests
yarn test:webauthn

# Run all tests including WebAuthn
yarn test:all
```

### Integration Tests

```bash
# Run blockchain integration tests
./test-integration.sh
```

The test suite covers:
- ✅ Contract deployment and initialization
- ✅ Signer management (add/remove)
- ✅ Threshold configuration
- ✅ Transaction execution with signatures
- ✅ Access control and permissions
- ✅ Upgrade functionality
- ✅ Emergency recovery scenarios
- ✅ Fallback handler integration
- ✅ ERC-1271 signature validation

## 🚢 Deployment

### Local Development
```bash
yarn deploy
```

### Testnet (Sepolia)
```bash
yarn deploy:testnet
```

### Mainnet
1. Configure mainnet RPC URL in `.env`
2. Update `hardhat.config.ts` with mainnet configuration
3. Run deployment with appropriate network flag

### Docker Deployment

#### Build Image
```bash
docker build -t infrasafe .
```

#### Run Container
```bash
docker run -p 5656:5656 -p 8545:8545 infrasafe
```

#### Docker Compose (Production)
```yaml
version: '3.8'
services:
  infrasafe:
    build: .
    ports:
      - "5656:5656"
      - "8545:8545"
    environment:
      - SEPOLIA_RPC_URL=${SEPOLIA_RPC_URL}
      - BLOCKCHAIN_PRIVATE_KEY=${BLOCKCHAIN_PRIVATE_KEY}
    volumes:
      - ./deployments:/app/deployments
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5656/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

## 🔒 Security Considerations

### Audit Recommendations

1. **Multi-Signature Security**
   - Always use threshold ≥ 2 for production deployments
   - Distribute private keys across multiple secure environments
   - Regularly rotate signer keys

2. **Upgrade Safety**
   - Use a multi-signature admin for upgrade authorization
   - Test upgrades thoroughly on testnets
   - Consider timelock delays for upgrade execution

3. **Fallback Handler Security**
   - Only register trusted and audited handler contracts
   - Monitor handler events for suspicious activity
   - Implement circuit breakers for high-value operations

4. **Access Control**
   - Regularly review role assignments
   - Use principle of least privilege
   - Monitor admin operations

### Known Limitations

- **Gas Costs**: Complex multisig operations have higher gas costs than EOA transactions
- **Upgrade Risks**: UUPS upgrades require careful access control management
- **Fallback Dependencies**: Extension functionality depends on external handler contracts

## 🛠️ Development

### Project Structure

```
infrasafe/
├── contracts/
│   └── infra-safe/
│       ├── InfraSafe.sol          # Main multisig contract
│       └── FallbackHandler.sol    # Extension system
├── scripts/
│   └── deploy.ts                  # Deployment script
├── test/
│   └── InfraSafe.test.ts         # Test suite
├── server/
│   └── index.ts                   # REST API server
├── typechain-types/               # Generated TypeScript types
├── artifacts/                     # Compiled contracts
├── deployments/                   # Deployment metadata
├── hardhat.config.ts             # Hardhat configuration
├── package.json                  # Dependencies and scripts
└── Dockerfile                    # Container configuration
```

### Adding Custom Extensions

1. **Create Handler Contract**
```solidity
contract CustomHandler {
    function customFunction(bytes calldata data) external returns (bytes memory) {
        // Custom logic here
        return abi.encode("success");
    }
}
```

2. **Register Handler**
```typescript
const selector = ethers.id("customFunction(bytes)").slice(0, 10);
await fallbackHandler.setHandler(selector, customHandler.address);
```

3. **Call Through InfraSafe**
```typescript
const calldata = ethers.concat([
    selector,
    ethers.AbiCoder.defaultAbiCoder().encode(["bytes"], [data])
]);

// Use fallback mechanism
await signer.sendTransaction({
    to: infraSafe.address,
    data: calldata
});
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes and add tests
4. Ensure all tests pass (`yarn test`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 📋 Scripts Reference

| Command | Description |
|---------|-------------|
| `yarn compile` | Compile smart contracts |
| `yarn deploy` | Deploy to local network |
| `yarn deploy:testnet` | Deploy to Sepolia testnet |
| `yarn test` | Run test suite |
| `yarn node` | Start local Hardhat node |
| `yarn serve` | Start ABI metadata server |
| `yarn start` | Full development setup |
| `yarn clean` | Clean artifacts and cache |
| `yarn typechain` | Generate TypeScript types |

## 🌟 Future Enhancements

### Planned Features

- **AI Agent Integration**: Native support for trusted AI agents with configurable permissions
- **Social Recovery**: Email/SMS-based recovery mechanisms
- **Biometric Authentication**: Hardware wallet integration with biometric verification
- **Cross-Chain Support**: Multi-chain deployment and asset management
- **Advanced Analytics**: Transaction pattern analysis and risk scoring
- **Mobile SDK**: React Native SDK for mobile wallet integration

### Roadmap

- **Q3 2025**: AI agent role implementation
- **Q4 2025**: Cross-chain bridge integration
- **Q1 2026**: Mobile SDK release
- **Q2 2026**: Advanced security features

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## 🤝 Support

- **Documentation**: [GitHub Wiki](../../wiki)
- **Issues**: [GitHub Issues](../../issues)
- **Discussions**: [GitHub Discussions](../../discussions)
- **Email**: infrasafe@infrasim.com

## 🏆 Acknowledgments

- **OpenZeppelin**: For providing battle-tested smart contract libraries
- **Gnosis Safe**: For pioneering multisig wallet architecture
- **Hardhat**: For the excellent development framework
- **Ethereum Community**: For continuous innovation in smart contract security

---

**⚠️ Disclaimer**: This software is provided "as is" without warranty. Always conduct thorough testing and security audits before deploying to mainnet with real funds.

---

Built with ❤️ by the InfraSim Team
