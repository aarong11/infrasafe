# InfraSafe WebAuthn API Specification

## Overview

The InfraSafe WebAuthn API provides passwordless authentication for Ethereum multisig wallets using WebAuthn (Web Authentication) standard. This API enables secure biometric and hardware key-based authentication for blockchain transactions.

## Base URL

```
Production: https://api.infrasafe.io
Development: http://localhost:3001
```

## Authentication

The API uses JWT (JSON Web Tokens) for session management after successful WebAuthn authentication.

### Headers

All authenticated requests must include:

```http
Authorization: Bearer <jwt_token>
Content-Type: application/json
Origin: <allowed_origin>
```

## Rate Limiting

- **Registration endpoints**: 5 requests per 15 minutes per IP
- **Authentication endpoints**: 10 requests per 15 minutes per IP  
- **Transaction endpoints**: 100 requests per hour per user
- **General endpoints**: 1000 requests per hour per IP

## Response Format

All API responses follow this standard format:

```typescript
interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}
```

### Success Response
```json
{
  "success": true,
  "data": {
    // Response data
  }
}
```

### Error Response
```json
{
  "success": false,
  "error": "Error description",
  "message": "Additional context (optional)"
}
```

## Endpoints

### Health & System

#### GET /health
Get server health status.

**Response:**
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "timestamp": "2025-07-09T19:23:50.772Z",
    "version": "1.0.0",
    "environment": "production"
  }
}
```

#### GET /docs
Get API documentation.

**Response:**
```json
{
  "success": true,
  "data": {
    "title": "InfraSafe WebAuthn API",
    "description": "Passwordless authentication API for InfraSafe multisig wallets",
    "version": "1.0.0",
    "endpoints": {
      // Full endpoint documentation
    }
  }
}
```

### WebAuthn Authentication

#### POST /webauthn/register/options
Generate WebAuthn registration options for new device registration.

**Request Body:**
```typescript
{
  username: string;           // 3-50 chars, alphanumeric + _ -
  walletAddress: string;      // Valid Ethereum address
  deviceName?: string;        // Optional device name (1-100 chars)
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "options": {
      "challenge": "base64-encoded-challenge",
      "rp": {
        "name": "InfraSafe",
        "id": "localhost"
      },
      "user": {
        "id": "user-uuid",
        "name": "username",
        "displayName": "username"
      },
      "pubKeyCredParams": [
        { "alg": -7, "type": "public-key" },
        { "alg": -257, "type": "public-key" }
      ],
      "timeout": 300000,
      "attestation": "none",
      "authenticatorSelection": {
        "authenticatorAttachment": "platform",
        "userVerification": "preferred",
        "residentKey": "preferred"
      },
      "excludeCredentials": []
    },
    "userId": "user-uuid"
  }
}
```

**Error Codes:**
- `409`: User already exists with this wallet address or username
- `400`: Invalid request data
- `429`: Rate limit exceeded

#### POST /webauthn/register/verify
Verify WebAuthn registration and complete device registration.

**Request Body:**
```typescript
{
  userId: string;             // UUID from registration options
  credential: {
    id: string;               // Credential ID
    rawId: string;            // Base64-encoded raw credential ID  
    response: {
      clientDataJSON: string; // Base64-encoded client data
      attestationObject: string; // Base64-encoded attestation
      transports?: string[];  // Optional transport methods
    };
    type: "public-key";
  };
  deviceName?: string;        // Optional device name
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "user-uuid",
      "username": "username",
      "walletAddress": "0x...",
      "createdAt": "2025-07-09T19:23:50.772Z"
    },
    "device": {
      "id": "device-uuid",
      "name": "Device Name",
      "credentialID": "base64-encoded-id",
      "createdAt": "2025-07-09T19:23:50.772Z"
    },
    "session": {
      "token": "jwt-token",
      "expiresAt": "2025-07-10T19:23:50.772Z"
    }
  }
}
```

#### POST /webauthn/login/options
Generate WebAuthn authentication options for login.

**Request Body:**
```typescript
{
  walletAddress?: string;     // Ethereum address OR
  username?: string;          // Username (one required)
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "options": {
      "challenge": "base64-encoded-challenge",
      "timeout": 300000,
      "rpId": "localhost",
      "allowCredentials": [
        {
          "id": "credential-id",
          "type": "public-key",
          "transports": ["internal", "hybrid"]
        }
      ],
      "userVerification": "preferred"
    },
    "deviceCount": 2,
    "hasDevices": true
  }
}
```

#### POST /webauthn/login/verify
Verify WebAuthn authentication and create session.

**Request Body:**
```typescript
{
  credential: {
    id: string;               // Credential ID
    rawId: string;            // Base64-encoded raw credential ID
    response: {
      clientDataJSON: string; // Base64-encoded client data
      authenticatorData: string; // Base64-encoded authenticator data
      signature: string;      // Base64-encoded signature
      userHandle?: string;    // Optional user handle
    };
    type: "public-key";
  };
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "user-uuid", 
      "username": "username",
      "walletAddress": "0x...",
      "lastLoginAt": "2025-07-09T19:23:50.772Z"
    },
    "session": {
      "token": "jwt-token",
      "expiresAt": "2025-07-10T19:23:50.772Z",
      "sessionId": "session-uuid"
    },
    "device": {
      "id": "device-uuid",
      "name": "Device Name",
      "lastUsedAt": "2025-07-09T19:23:50.772Z"
    }
  }
}
```

#### GET /webauthn/me
Get current authenticated user information.

**Headers:** `Authorization: Bearer <token>`

**Response:**
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "user-uuid",
      "username": "username", 
      "walletAddress": "0x...",
      "createdAt": "2025-07-09T19:23:50.772Z",
      "lastLoginAt": "2025-07-09T19:23:50.772Z"
    },
    "session": {
      "sessionId": "session-uuid",
      "issuedAt": "2025-07-09T19:23:50.772Z",
      "expiresAt": "2025-07-10T19:23:50.772Z"
    }
  }
}
```

#### GET /webauthn/devices
Get user's registered devices.

**Headers:** `Authorization: Bearer <token>`

**Response:**
```json
{
  "success": true,
  "data": {
    "devices": [
      {
        "id": "device-uuid",
        "name": "iPhone Touch ID",
        "credentialDeviceType": "singleDevice",
        "credentialBackedUp": false,
        "transports": ["internal"],
        "createdAt": "2025-07-09T19:23:50.772Z",
        "lastUsedAt": "2025-07-09T19:23:50.772Z"
      }
    ],
    "totalCount": 1
  }
}
```

#### DELETE /webauthn/devices/:deviceId
Remove a registered device.

**Headers:** `Authorization: Bearer <token>`

**Response:**
```json
{
  "success": true,
  "data": {
    "message": "Device removed successfully"
  }
}
```

#### POST /webauthn/refresh
Refresh authentication token.

**Headers:** `Authorization: Bearer <token>`

**Response:**
```json
{
  "success": true,
  "data": {
    "token": "new-jwt-token",
    "expiresAt": "2025-07-10T19:23:50.772Z"
  }
}
```

#### POST /webauthn/logout
Logout and invalidate session.

**Headers:** `Authorization: Bearer <token>`

**Response:**
```json
{
  "success": true,
  "data": {
    "message": "Logged out successfully"
  }
}
```

### Wallet Management

#### GET /wallet/:address/status
Get wallet status and user permissions.

**Headers:** `Authorization: Bearer <token>`

**Parameters:**
- `address`: Ethereum wallet address

**Response:**
```json
{
  "success": true,
  "data": {
    "address": "0x...",
    "threshold": 2,
    "signerCount": 3,
    "signers": ["0x...", "0x...", "0x..."],
    "userIsSigner": true,
    "userRoles": ["signer"],
    "nonce": 42,
    "balance": "1000000000000000000"
  }
}
```

#### POST /wallet/:address/transactions/prepare
Prepare a transaction for signing.

**Headers:** `Authorization: Bearer <token>`

**Request Body:**
```typescript
{
  to: string;               // Target address
  value: string;            // Wei amount as string
  data: string;             // Hex-encoded transaction data
  description?: string;     // Optional description
  gasLimit?: string;        // Optional gas limit
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "transactionId": "tx-uuid",
    "hash": "0x...",
    "nonce": 42,
    "gasEstimate": "21000",
    "requiresSignatures": 2,
    "currentSignatures": 0
  }
}
```

#### POST /wallet/:address/transactions/submit
Submit a signed transaction.

**Headers:** `Authorization: Bearer <token>`

**Request Body:**
```typescript
{
  to: string;               // Target address
  value: string;            // Wei amount as string
  data: string;             // Hex-encoded transaction data
  signatures: string[];     // Array of hex-encoded signatures
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "txHash": "0x...",
    "status": "submitted",
    "blockNumber": null,
    "gasUsed": null
  }
}
```

#### POST /wallet/:address/transactions/simulate
Simulate a transaction without execution.

**Headers:** `Authorization: Bearer <token>`

**Request Body:**
```typescript
{
  to: string;               // Target address
  value?: string;           // Wei amount as string (optional)
  data: string;             // Hex-encoded transaction data
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "success": true,
    "returnData": "0x...",
    "gasUsed": "45231",
    "error": null
  }
}
```

#### GET /wallet/:address/transactions
Get wallet transaction history.

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**
- `page`: Page number (default: 1)
- `limit`: Items per page (default: 20, max: 100)

**Response:**
```json
{
  "success": true,
  "data": {
    "transactions": [
      {
        "txHash": "0x...",
        "to": "0x...",
        "value": "1000000000000000000",
        "data": "0x...",
        "nonce": 42,
        "signatures": ["0x...", "0x..."],
        "submittedBy": "0x...",
        "submittedAt": "2025-07-09T19:23:50.772Z",
        "blockNumber": 12345,
        "gasUsed": "21000"
      }
    ],
    "pagination": {
      "currentPage": 1,
      "totalPages": 5,
      "totalItems": 100,
      "hasNextPage": true,
      "hasPrevPage": false
    }
  }
}
```

## Error Codes

### HTTP Status Codes

- `200`: Success
- `400`: Bad Request - Invalid input data
- `401`: Unauthorized - Invalid or missing authentication
- `403`: Forbidden - Insufficient permissions
- `404`: Not Found - Resource not found
- `409`: Conflict - Resource already exists
- `429`: Too Many Requests - Rate limit exceeded
- `500`: Internal Server Error - Server error

### Application Error Codes

#### WebAuthn Errors
- `USER_ALREADY_EXISTS`: User already registered
- `USER_NOT_FOUND`: User not found
- `DEVICE_NOT_FOUND`: Device not found
- `INVALID_CHALLENGE`: Invalid or expired challenge
- `REGISTRATION_FAILED`: WebAuthn registration failed
- `AUTHENTICATION_FAILED`: WebAuthn authentication failed
- `DEVICE_LIMIT_EXCEEDED`: Too many devices registered

#### Authentication Errors
- `INVALID_TOKEN`: Invalid JWT token
- `TOKEN_EXPIRED`: JWT token expired
- `SESSION_NOT_FOUND`: Session not found
- `INSUFFICIENT_PERMISSIONS`: User lacks required permissions

#### Contract Errors
- `CONTRACT_NOT_FOUND`: Smart contract not found
- `INVALID_SIGNER`: User is not a valid signer
- `INSUFFICIENT_SIGNATURES`: Not enough signatures
- `TRANSACTION_FAILED`: Transaction execution failed
- `SIMULATION_FAILED`: Transaction simulation failed

## Security Considerations

### CORS
The API enforces strict CORS policies. Only whitelisted origins are allowed:
- `https://app.infrasafe.io` (production)
- `http://localhost:3000` (development)
- `http://localhost:3001` (development)

### Rate Limiting
Rate limits are enforced per IP address and per user. Exceeded limits return `429` status with retry information.

### User-Agent Validation
Requests must include a valid User-Agent header. Suspicious or missing User-Agents may be rejected.

### Content-Type Validation
POST requests must use `application/json` content type.

### WebAuthn Security
- Challenges expire after 5 minutes
- User verification is preferred but not required
- Attestation is not required for registration
- Counter verification prevents replay attacks

## SDK Integration Examples

See the [Integration Guide](./INTEGRATION_GUIDE.md) for complete implementation examples in JavaScript/TypeScript, React, and Node.js.
