# InfraSafe WebAuthn Authentication Server

![InfraSafe WebAuthn](https://img.shields.io/badge/InfraSafe-WebAuthn-blue)
![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-green)
![Node.js](https://img.shields.io/badge/Node.js-18+-green)
![Express](https://img.shields.io/badge/Express-4.18+-blue)

A production-ready **passwordless authentication server** for **InfraSafe**, providing WebAuthn-based biometric authentication integrated with Ethereum smart contracts.

## 🎯 Overview

This WebAuthn server enables users to authenticate with InfraSafe multisig wallets using:

- **🔐 Biometric Authentication**: Fingerprint, Face ID, Windows Hello
- **🔑 Hardware Security Keys**: YubiKey, Titan Key, etc.
- **📱 Platform Authenticators**: Built-in device authenticators
- **🏗️ Smart Contract Integration**: Direct integration with InfraSafe contracts
- **🛡️ Enterprise Security**: JWT sessions, rate limiting, CORS protection

## 🚀 Quick Start

### Prerequisites

- Node.js 18+ 
- npm or yarn
- InfraSafe contracts deployed and ABI server running
- Ethereum RPC endpoint

### 1. Installation

```bash
# Clone the repository
cd webauthn-server

# Install dependencies
npm install

# Copy environment template
cp .env.example .env
```

### 2. Configuration

Edit `.env` file with your settings:

```bash
# Required settings
JWT_SECRET=your-super-secure-jwt-secret-key-here
COOKIE_SECRET=your-super-secure-cookie-secret-key-here
ETH_RPC_URL=http://localhost:8545

# WebAuthn settings
RP_NAME=InfraSafe
RP_ID=localhost
ORIGIN=http://localhost:3001

# ABI server (must be running)
ABI_SERVER_URL=http://localhost
ABI_SERVER_PORT=5656
```

### 3. Start the Server

```bash
# Development mode
npm run webauthn-server

# Or using the root project
npm run webauthn-server
```

The server will start at `http://localhost:3001`

## 📋 API Endpoints

### 🔐 Authentication

#### Register New Device
```http
POST /webauthn/register/options
Content-Type: application/json

{
  "username": "alice",
  "walletAddress": "0x1234...5678",
  "deviceName": "iPhone Touch ID"
}
```

#### Complete Registration
```http
POST /webauthn/register/verify
Content-Type: application/json

{
  "userId": "uuid-here",
  "credential": { /* WebAuthn PublicKeyCredential */ },
  "deviceName": "iPhone Touch ID"
}
```

#### Login Options
```http
POST /webauthn/login/options
Content-Type: application/json

{
  "walletAddress": "0x1234...5678"
}
```

#### Complete Login
```http
POST /webauthn/login/verify
Content-Type: application/json

{
  "credential": { /* WebAuthn PublicKeyCredential */ }
}
```

#### Get User Info
```http
GET /webauthn/me
Authorization: Bearer <jwt-token>
```

### 🏦 Wallet Operations

#### Get Wallet Status
```http
GET /wallet/0x1234...5678/status
Authorization: Bearer <jwt-token>
```

#### Submit Transaction
```http
POST /wallet/0x1234...5678/submit
Authorization: Bearer <jwt-token>
Content-Type: application/json

{
  "to": "0xrecipient...",
  "value": "1000000000000000000",
  "data": "0x",
  "signatures": ["0x...", "0x..."]
}
```

#### Simulate Transaction
```http
POST /wallet/0x1234...5678/simulate
Authorization: Bearer <jwt-token>
Content-Type: application/json

{
  "to": "0xrecipient...",
  "value": "1000000000000000000",
  "data": "0x"
}
```

## 🏗️ Architecture

### Components

```
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│   WebAuthn Client   │    │  WebAuthn Server    │    │  InfraSafe Contract │
│                     │    │                     │    │                     │
│ • Browser/Mobile    │◄──►│ • Authentication    │◄──►│ • Multisig Logic    │
│ • Biometric Auth    │    │ • Session Mgmt      │    │ • Signer Validation │
│ • Credential Mgmt   │    │ • Contract Calls    │    │ • Transaction Exec  │
└─────────────────────┘    └─────────────────────┘    └─────────────────────┘
                                       │
                                       ▼
                           ┌─────────────────────┐
                           │    ABI Server       │
                           │                     │
                           │ • Contract Meta     │
                           │ • ABI Definitions   │
                           │ • Address Registry  │
                           └─────────────────────┘
```

### Security Layers

1. **🌐 Network Security**
   - CORS validation
   - Rate limiting
   - IP validation
   - Origin verification

2. **🔐 Authentication Security**
   - WebAuthn challenge/response
   - JWT token validation
   - Session management
   - Device tracking

3. **🏗️ Contract Security**
   - Signer role validation
   - Transaction verification
   - Nonce management
   - Signature validation

## 🧪 Testing

### Unit Tests
```bash
npm run test:webauthn
```

### Integration Tests
```bash
npm run test:integration
```

### End-to-End Tests
```bash
npm run test:e2e
```

### Test with Real WebAuthn

The server includes Playwright tests that simulate real WebAuthn interactions:

```bash
# Install Playwright browsers
npx playwright install

# Run E2E tests
npm run test:e2e
```

## 🔒 Security Features

### WebAuthn Security
- **Challenge Uniqueness**: Cryptographically secure random challenges
- **Origin Binding**: Strict origin validation for all WebAuthn operations
- **Replay Protection**: Challenge expiration and one-time use
- **Device Attestation**: Optional attestation validation for high-security scenarios

### Session Security
- **JWT Tokens**: Cryptographically signed session tokens
- **Session Binding**: Tokens bound to specific devices and IPs
- **Automatic Expiration**: Configurable session timeouts
- **Refresh Mechanism**: Secure token refresh without re-authentication

### API Security
- **Rate Limiting**: Prevents brute force and DoS attacks
- **CORS Protection**: Strict cross-origin request validation
- **Input Validation**: Schema-based request validation
- **Error Handling**: Secure error responses without information leakage

### Smart Contract Security
- **Role Verification**: On-chain signer role validation
- **Transaction Verification**: Signature and nonce validation
- **Access Control**: Wallet ownership verification
- **Audit Logging**: Comprehensive transaction and auth logging

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `WEBAUTHN_PORT` | Server port | 3001 | No |
| `JWT_SECRET` | JWT signing secret | - | **Yes** |
| `COOKIE_SECRET` | Cookie signing secret | - | **Yes** |
| `ETH_RPC_URL` | Ethereum RPC endpoint | - | **Yes** |
| `RP_NAME` | WebAuthn relying party name | InfraSafe | No |
| `RP_ID` | WebAuthn relying party ID | localhost | No |
| `ORIGIN` | WebAuthn origin | http://localhost:3001 | No |
| `CORS_ORIGINS` | Allowed CORS origins | localhost origins | No |

### Production Configuration

For production deployment:

```bash
# Security
JWT_SECRET=<64-character-random-string>
COOKIE_SECRET=<64-character-random-string>

# WebAuthn
RP_ID=your-domain.com
ORIGIN=https://your-domain.com
CORS_ORIGINS=https://your-domain.com,https://app.your-domain.com

# Network
ETH_RPC_URL=https://mainnet.infura.io/v3/your-project-id
ETH_CHAIN_ID=1

# Rate limiting
RATE_LIMIT_MAX=50
RATE_LIMIT_WINDOW=900000
```

## 📊 Monitoring & Logging

### Health Checks

```http
GET /health
GET /webauthn/health
GET /wallet/health
```

### Logging Levels

- **ERROR**: Authentication failures, contract errors
- **WARN**: Rate limit hits, suspicious activity
- **INFO**: Successful operations, session events
- **DEBUG**: Detailed operation traces

### Metrics

The server logs comprehensive metrics for:
- Authentication success/failure rates
- Transaction submission rates
- WebAuthn device distribution
- API endpoint usage
- Error rates by category

## 🚀 Deployment

### Docker Deployment

```dockerfile
FROM node:20-alpine

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY webauthn-server/ ./webauthn-server/
EXPOSE 3001

CMD ["npm", "run", "webauthn-server"]
```

### Production Checklist

- [ ] Generate secure `JWT_SECRET` and `COOKIE_SECRET`
- [ ] Configure production `RP_ID` and `ORIGIN`
- [ ] Set up HTTPS with valid SSL certificates
- [ ] Configure production Ethereum RPC endpoint
- [ ] Set up monitoring and alerting
- [ ] Configure log aggregation
- [ ] Set up backup and recovery procedures
- [ ] Test WebAuthn with real devices
- [ ] Validate CORS configuration
- [ ] Configure rate limiting for production load

## 🔗 Integration Examples

### Frontend Integration

```typescript
// Register new WebAuthn device
const registerDevice = async (username: string, walletAddress: string) => {
  // Get registration options
  const optionsResponse = await fetch('/webauthn/register/options', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, walletAddress })
  });
  const { options } = await optionsResponse.json();
  
  // Create credential
  const credential = await navigator.credentials.create({
    publicKey: options
  });
  
  // Verify registration
  const verifyResponse = await fetch('/webauthn/register/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      userId: options.user.id,
      credential: credential.toJSON()
    })
  });
  
  return verifyResponse.json();
};

// Authenticate with WebAuthn
const authenticateUser = async (walletAddress: string) => {
  // Get authentication options
  const optionsResponse = await fetch('/webauthn/login/options', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ walletAddress })
  });
  const { options } = await optionsResponse.json();
  
  // Get credential
  const credential = await navigator.credentials.get({
    publicKey: options
  });
  
  // Verify authentication
  const verifyResponse = await fetch('/webauthn/login/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      credential: credential.toJSON()
    })
  });
  
  return verifyResponse.json();
};
```

### Smart Contract Integration

```typescript
// Submit transaction via WebAuthn
const submitTransaction = async (
  walletAddress: string,
  to: string,
  value: string,
  data: string,
  signatures: string[],
  authToken: string
) => {
  const response = await fetch(`/wallet/${walletAddress}/submit`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${authToken}`
    },
    body: JSON.stringify({ to, value, data, signatures })
  });
  
  return response.json();
};
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes and add tests
4. Ensure all tests pass (`npm run test`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

## 🏆 Acknowledgments

- **WebAuthn Specification**: W3C and FIDO Alliance
- **SimpleWebAuthn**: For excellent WebAuthn library
- **OpenZeppelin**: For secure smart contract patterns
- **Express.js**: For robust HTTP server framework

---

**⚠️ Security Notice**: This is a reference implementation. Conduct thorough security audits before production deployment with real assets.

---

Built with ❤️ by the InfraSim Team
