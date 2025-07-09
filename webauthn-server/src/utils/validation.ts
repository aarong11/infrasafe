import { z } from 'zod';
import { isAddress } from 'ethers';

// Base schemas
export const EthereumAddressSchema = z.string().refine(
  (address) => isAddress(address),
  { message: 'Invalid Ethereum address' }
);

export const HexStringSchema = z.string().regex(/^0x[a-fA-F0-9]*$/, 'Invalid hex string');

export const UUIDSchema = z.string().uuid('Invalid UUID format');

// User schemas
export const CreateUserSchema = z.object({
  username: z.string()
    .min(3, 'Username must be at least 3 characters')
    .max(50, 'Username must be less than 50 characters')
    .regex(/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, underscores, and hyphens'),
  walletAddress: EthereumAddressSchema,
});

// WebAuthn schemas
export const RegistrationStartSchema = z.object({
  username: z.string().min(3).max(50),
  walletAddress: EthereumAddressSchema,
  deviceName: z.string().min(1).max(100).optional(),
});

export const RegistrationFinishSchema = z.object({
  userId: UUIDSchema,
  credential: z.object({
    id: z.string(),
    rawId: z.string(),
    response: z.object({
      clientDataJSON: z.string(),
      attestationObject: z.string(),
      transports: z.array(z.string()).optional(),
    }),
    type: z.literal('public-key'),
  }),
  deviceName: z.string().min(1).max(100).optional(),
});

export const AuthenticationStartSchema = z.object({
  walletAddress: EthereumAddressSchema.optional(),
  username: z.string().optional(),
}).refine(
  (data) => data.walletAddress || data.username,
  { message: 'Either walletAddress or username must be provided' }
);

export const AuthenticationFinishSchema = z.object({
  credential: z.object({
    id: z.string(),
    rawId: z.string(),
    response: z.object({
      clientDataJSON: z.string(),
      authenticatorData: z.string(),
      signature: z.string(),
      userHandle: z.string().optional(),
    }),
    type: z.literal('public-key'),
  }),
});

// Transaction schemas
export const TransactionRequestSchema = z.object({
  to: EthereumAddressSchema,
  value: z.string().regex(/^\d+$/, 'Value must be a valid integer string'),
  data: HexStringSchema,
  description: z.string().max(500).optional(),
  gasLimit: z.string().regex(/^\d+$/, 'Gas limit must be a valid integer string').optional(),
});

export const TransactionSubmissionSchema = z.object({
  to: EthereumAddressSchema,
  value: z.string().regex(/^\d+$/, 'Value must be a valid integer string'),
  data: HexStringSchema,
  signatures: z.array(HexStringSchema).min(1, 'At least one signature required'),
});

export const SimulationRequestSchema = z.object({
  to: EthereumAddressSchema,
  value: z.string().regex(/^\d+$/, 'Value must be a valid integer string').optional(),
  data: HexStringSchema,
});

// Wallet schemas
export const WalletAddressSchema = z.object({
  address: EthereumAddressSchema,
});

// Query schemas
export const PaginationSchema = z.object({
  page: z.string().regex(/^\d+$/).transform(Number).optional(),
  limit: z.string().regex(/^\d+$/).transform(Number).optional(),
});

// Validation helper functions
export function validateEthereumAddress(address: string): boolean {
  return isAddress(address);
}

export function validateHexString(hex: string): boolean {
  return /^0x[a-fA-F0-9]*$/.test(hex);
}

export function validateUUID(uuid: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuid);
}

// Sanitization helpers
export function sanitizeString(input: string, maxLength: number = 255): string {
  return input.trim().slice(0, maxLength);
}

export function normalizeEthereumAddress(address: string): string {
  return address.toLowerCase();
}

// Rate limiting helpers
export function createRateLimitKey(ip: string, endpoint: string): string {
  return `rate_limit:${ip}:${endpoint}`;
}

export function createUserRateLimitKey(userId: string, endpoint: string): string {
  return `user_rate_limit:${userId}:${endpoint}`;
}
