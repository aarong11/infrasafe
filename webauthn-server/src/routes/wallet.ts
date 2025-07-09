import { Router, Request, Response } from 'express';
import { 
  WalletAddressSchema,
  TransactionRequestSchema,
  TransactionSubmissionSchema,
  SimulationRequestSchema
} from '../utils/validation';
import { validateRequest, asyncHandler } from '../middleware/error';
import { transactionRateLimit } from '../middleware/rateLimit';
import { validateContentType } from '../middleware/security';
import { authenticate, requireWalletOwnership } from '../middleware/auth';
import { contractService } from '../services/contract';
import { storageService } from '../services/storage';
import { logger } from '../utils/logger';
import { ApiResponse, ContractError, TransactionSubmission } from '../types';
import { v4 as uuidv4 } from 'uuid';

const router = Router();

// Apply common middleware
router.use(validateContentType());
router.use(authenticate);

/**
 * GET /wallet/:address/status
 * Get wallet status including signers, threshold, and user permissions
 */
router.get(
  '/:address/status',
  validateRequest(WalletAddressSchema, 'params'),
  requireWalletOwnership,
  asyncHandler(async (req: Request, res: Response) => {
    const { address } = req.params;
    const user = req.user;

    // Get wallet status
    const status = await contractService.getWalletStatus(address, user.walletAddress);

    logger.contract('Wallet status requested', {
      walletAddress: address,
      userId: user.id,
      userIsSigner: status.userIsSigner,
    });

    const response: ApiResponse = {
      success: true,
      data: status,
    };

    res.json(response);
  })
);

/**
 * POST /wallet/:address/submit
 * Submit a multisig transaction
 */
router.post(
  '/:address/submit',
  transactionRateLimit,
  validateRequest(WalletAddressSchema, 'params'),
  validateRequest(TransactionSubmissionSchema),
  requireWalletOwnership,
  asyncHandler(async (req: Request, res: Response) => {
    const { address } = req.params;
    const { to, value, data, signatures } = req.body;
    const user = req.user;

    // Verify user is a signer
    const isSigner = await contractService.verifyUserIsSigner(address, user.walletAddress);
    if (!isSigner) {
      throw new ContractError('User is not a signer for this wallet', 'NOT_A_SIGNER', address, 403);
    }

    // Execute the transaction
    const txHash = await contractService.executeTransaction(address, to, value, data, signatures);

    // Save transaction record
    const transaction: TransactionSubmission = {
      txHash,
      to,
      value,
      data,
      nonce: 0, // Will be updated when we get the actual nonce
      signatures,
      submittedBy: user.id,
      submittedAt: new Date(),
    };

    await storageService.saveTransaction(transaction);

    logger.contract('Transaction submitted', {
      txHash,
      walletAddress: address,
      to,
      value,
      userId: user.id,
      signaturesCount: signatures.length,
    });

    const response: ApiResponse = {
      success: true,
      data: {
        txHash,
        to,
        value,
        data,
        signatures,
        submittedAt: transaction.submittedAt,
      },
      message: 'Transaction submitted successfully',
    };

    res.json(response);
  })
);

/**
 * POST /wallet/:address/simulate
 * Simulate a transaction without executing it
 */
router.post(
  '/:address/simulate',
  validateRequest(WalletAddressSchema, 'params'),
  validateRequest(SimulationRequestSchema),
  requireWalletOwnership,
  asyncHandler(async (req: Request, res: Response) => {
    const { address } = req.params;
    const { to, value = '0', data } = req.body;
    const user = req.user;

    // Verify user is a signer
    const isSigner = await contractService.verifyUserIsSigner(address, user.walletAddress);
    if (!isSigner) {
      throw new ContractError('User is not a signer for this wallet', 'NOT_A_SIGNER', address, 403);
    }

    // For simulation, we'll use empty signatures - this is just a static call
    const emptySignatures: string[] = [];

    // Simulate the transaction
    const result = await contractService.simulateTransaction(
      address,
      to,
      value,
      data,
      emptySignatures
    );

    logger.contract('Transaction simulated', {
      walletAddress: address,
      to,
      value,
      success: result.success,
      userId: user.id,
    });

    const response: ApiResponse = {
      success: true,
      data: result,
    };

    res.json(response);
  })
);

/**
 * GET /wallet/:address/transactions
 * Get transaction history for the wallet
 */
router.get(
  '/:address/transactions',
  validateRequest(WalletAddressSchema, 'params'),
  requireWalletOwnership,
  asyncHandler(async (req: Request, res: Response) => {
    const { address } = req.params;
    const user = req.user;

    // Get user's transactions for this wallet
    const transactions = await storageService.getTransactionsByUser(user.id);

    // Filter transactions for this wallet address
    const walletTransactions = transactions.filter(tx => 
      // This is a simplified filter - in a real implementation, 
      // you'd need to check which transactions are related to this wallet
      true
    );

    logger.contract('Transaction history requested', {
      walletAddress: address,
      userId: user.id,
      transactionCount: walletTransactions.length,
    });

    const response: ApiResponse = {
      success: true,
      data: {
        transactions: walletTransactions.map(tx => ({
          txHash: tx.txHash,
          to: tx.to,
          value: tx.value,
          data: tx.data,
          nonce: tx.nonce,
          signaturesCount: tx.signatures.length,
          submittedAt: tx.submittedAt,
        })),
        total: walletTransactions.length,
      },
    };

    res.json(response);
  })
);

/**
 * GET /wallet/:address/signers
 * Get list of signers for the wallet
 */
router.get(
  '/:address/signers',
  validateRequest(WalletAddressSchema, 'params'),
  requireWalletOwnership,
  asyncHandler(async (req: Request, res: Response) => {
    const { address } = req.params;
    const user = req.user;

    // Get wallet status to get signers
    const status = await contractService.getWalletStatus(address, user.walletAddress);

    logger.contract('Signers list requested', {
      walletAddress: address,
      userId: user.id,
      signerCount: status.signerCount,
    });

    const response: ApiResponse = {
      success: true,
      data: {
        signers: status.signers,
        threshold: status.threshold,
        signerCount: status.signerCount,
        userIsSigner: status.userIsSigner,
      },
    };

    res.json(response);
  })
);

/**
 * GET /wallet/:address/nonce
 * Get current nonce for the wallet
 */
router.get(
  '/:address/nonce',
  validateRequest(WalletAddressSchema, 'params'),
  requireWalletOwnership,
  asyncHandler(async (req: Request, res: Response) => {
    const { address } = req.params;
    const user = req.user;

    // Get wallet status to get nonce
    const status = await contractService.getWalletStatus(address, user.walletAddress);

    logger.contract('Nonce requested', {
      walletAddress: address,
      userId: user.id,
      nonce: status.nonce,
    });

    const response: ApiResponse = {
      success: true,
      data: {
        nonce: status.nonce,
      },
    };

    res.json(response);
  })
);

/**
 * POST /wallet/:address/transaction-hash
 * Generate transaction hash for signing
 */
router.post(
  '/:address/transaction-hash',
  validateRequest(WalletAddressSchema, 'params'),
  validateRequest(TransactionRequestSchema),
  requireWalletOwnership,
  asyncHandler(async (req: Request, res: Response) => {
    const { address } = req.params;
    const { to, value, data } = req.body;
    const user = req.user;

    // Verify user is a signer
    const isSigner = await contractService.verifyUserIsSigner(address, user.walletAddress);
    if (!isSigner) {
      throw new ContractError('User is not a signer for this wallet', 'NOT_A_SIGNER', address, 403);
    }

    // Get current nonce
    const status = await contractService.getWalletStatus(address);
    const nonce = status.nonce;

    // Generate transaction hash
    const txHash = await contractService.getTransactionHash(address, to, value, data, nonce);

    logger.contract('Transaction hash generated', {
      walletAddress: address,
      to,
      value,
      nonce,
      txHash,
      userId: user.id,
    });

    const response: ApiResponse = {
      success: true,
      data: {
        txHash,
        to,
        value,
        data,
        nonce,
      },
    };

    res.json(response);
  })
);

/**
 * GET /wallet/:address/balance
 * Get wallet ETH balance
 */
router.get(
  '/:address/balance',
  validateRequest(WalletAddressSchema, 'params'),
  requireWalletOwnership,
  asyncHandler(async (req: Request, res: Response) => {
    const { address } = req.params;
    const user = req.user;

    // Get wallet status to get balance
    const status = await contractService.getWalletStatus(address, user.walletAddress);

    logger.contract('Balance requested', {
      walletAddress: address,
      userId: user.id,
      balance: status.balance,
    });

    const response: ApiResponse = {
      success: true,
      data: {
        balance: status.balance,
        address: status.address,
      },
    };

    res.json(response);
  })
);

/**
 * GET /wallet/health
 * Health check for wallet service
 */
router.get(
  '/health',
  asyncHandler(async (req: Request, res: Response) => {
    const health = await contractService.healthCheck();

    const response: ApiResponse = {
      success: true,
      data: health,
    };

    res.json(response);
  })
);

export default router;
