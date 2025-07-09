import { 
  AuthenticatorDevice,
  RegistrationResponseJSON,
  AuthenticationResponseJSON 
} from '@simplewebauthn/types';

export interface User {
  id: string;
  username: string;
  walletAddress: string;
  createdAt: Date;
  lastLoginAt?: Date;
}

export interface UserDevice extends AuthenticatorDevice {
  id: string;
  userId: string;
  name: string;
  credentialID: Uint8Array;
  credentialPublicKey: Uint8Array;
  counter: number;
  credentialDeviceType: 'singleDevice' | 'multiDevice';
  credentialBackedUp: boolean;
  transports?: AuthenticatorTransport[];
  createdAt: Date;
  lastUsedAt?: Date;
}

export interface RegistrationChallenge {
  challenge: string;
  userId: string;
  expiresAt: Date;
  userVerification: UserVerificationRequirement;
}

export interface AuthenticationChallenge {
  challenge: string;
  allowCredentials?: PublicKeyCredentialDescriptor[];
  expiresAt: Date;
  userVerification: UserVerificationRequirement;
}

export interface AuthSession {
  sessionId: string;
  userId: string;
  walletAddress: string;
  issuedAt: Date;
  expiresAt: Date;
  deviceId: string;
  ipAddress: string;
  userAgent: string;
}

export interface ContractMetadata {
  address: string;
  abi: any[];
  signatures?: string[];
  implementationAddress?: string;
  proxyAdminAddress?: string;
}

export interface ContractRegistry {
  [contractName: string]: ContractMetadata;
}

export interface WalletStatus {
  address: string;
  threshold: number;
  signerCount: number;
  signers: string[];
  userIsSigner: boolean;
  userRoles: string[];
  nonce: number;
  balance: string;
}

export interface TransactionRequest {
  to: string;
  value: string;
  data: string;
  description?: string;
  gasLimit?: string;
}

export interface TransactionSubmission {
  txHash: string;
  to: string;
  value: string;
  data: string;
  nonce: number;
  signatures: string[];
  submittedBy: string;
  submittedAt: Date;
}

export interface SimulationResult {
  success: boolean;
  returnData?: string;
  gasUsed: string;
  error?: string;
}

// WebAuthn related types
export interface RegistrationOptions {
  challenge: string;
  rp: {
    name: string;
    id: string;
  };
  user: {
    id: string;
    name: string;
    displayName: string;
  };
  pubKeyCredParams: {
    alg: number;
    type: 'public-key';
  }[];
  timeout: number;
  attestation: AttestationConveyancePreference;
  excludeCredentials?: PublicKeyCredentialDescriptor[];
  authenticatorSelection: {
    authenticatorAttachment?: AuthenticatorAttachment;
    userVerification: UserVerificationRequirement;
    residentKey?: ResidentKeyRequirement;
  };
}

export interface AuthenticationOptions {
  challenge: string;
  timeout: number;
  rpId: string;
  allowCredentials?: PublicKeyCredentialDescriptor[];
  userVerification: UserVerificationRequirement;
}

// API Response types
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

export interface JWTPayload {
  userId: string;
  walletAddress: string;
  sessionId: string;
  deviceId: string;
  iat: number;
  exp: number;
}

// Error types
export class WebAuthnError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode: number = 400
  ) {
    super(message);
    this.name = 'WebAuthnError';
  }
}

export class ContractError extends Error {
  constructor(
    message: string,
    public code: string,
    public contractAddress?: string,
    public statusCode: number = 500
  ) {
    super(message);
    this.name = 'ContractError';
  }
}

export class AuthenticationError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode: number = 401
  ) {
    super(message);
    this.name = 'AuthenticationError';
  }
}
