import { ethers } from 'ethers';
import { ContractMetadata, ContractRegistry, WalletStatus, ContractError } from '../types';
import { config } from '../utils/config';
import { logger } from '../utils/logger';
import { storageService } from './storage';

/**
 * Service for interacting with InfraSafe smart contracts
 */
class ContractService {
  private provider: ethers.Provider;
  private signer?: ethers.Signer;
  private contractRegistry: ContractRegistry = {};
  private lastRegistryUpdate: number = 0;
  private readonly REGISTRY_CACHE_TIME = 5 * 60 * 1000; // 5 minutes

  constructor() {
    this.provider = new ethers.JsonRpcProvider(config.ethRpcUrl);
    
    if (config.ethPrivateKey) {
      this.signer = new ethers.Wallet(config.ethPrivateKey, this.provider);
    }
  }

  /**
   * Load contract metadata from the ABI server
   */
  async loadContractRegistry(): Promise<void> {
    const now = Date.now();
    
    // Check if we need to refresh the registry
    if (now - this.lastRegistryUpdate < this.REGISTRY_CACHE_TIME) {
      return;
    }

    try {
      const abiServerUrl = `${config.abiServerUrl}:${config.abiServerPort}`;
      const response = await fetch(`${abiServerUrl}/contracts`);
      
      if (!response.ok) {
        throw new Error(`ABI server returned ${response.status}: ${response.statusText}`);
      }

      const contracts: ContractRegistry = await response.json();
      this.contractRegistry = contracts;
      this.lastRegistryUpdate = now;
      
      logger.contract('Contract registry loaded', { 
        contractCount: Object.keys(contracts).length,
        contracts: Object.keys(contracts)
      });
    } catch (error) {
      logger.error('Failed to load contract registry', { error: error instanceof Error ? error.message : error });
      throw new ContractError('Failed to load contract metadata', 'REGISTRY_LOAD_FAILED');
    }
  }

  /**
   * Get contract metadata by name
   */
  async getContractMetadata(contractName: string): Promise<ContractMetadata> {
    await this.loadContractRegistry();
    
    const metadata = this.contractRegistry[contractName];
    if (!metadata) {
      throw new ContractError(`Contract '${contractName}' not found`, 'CONTRACT_NOT_FOUND');
    }
    
    return metadata;
  }

  /**
   * Get contract instance
   */
  async getContract(contractName: string): Promise<ethers.Contract> {
    const metadata = await this.getContractMetadata(contractName);
    return new ethers.Contract(metadata.address, metadata.abi, this.provider);
  }

  /**
   * Get contract instance with signer
   */
  async getContractWithSigner(contractName: string): Promise<ethers.Contract> {
    if (!this.signer) {
      throw new ContractError('No signer available for contract interaction', 'NO_SIGNER');
    }
    
    const metadata = await this.getContractMetadata(contractName);
    return new ethers.Contract(metadata.address, metadata.abi, this.signer);
  }

  /**
   * Get wallet status for a given address
   */
  async getWalletStatus(walletAddress: string, userAddress?: string): Promise<WalletStatus> {
    try {
      const infraSafe = await this.getContract('InfraSafe');
      
      // Get basic wallet info
      const [threshold, signerCount, nonce] = await Promise.all([
        infraSafe.threshold(),
        infraSafe.getSignerCount(),
        infraSafe.nonce()
      ]);

      // Get balance
      const balance = await this.provider.getBalance(walletAddress);

      // Get signers
      const signers: string[] = [];
      for (let i = 0; i < signerCount; i++) {
        const signer = await infraSafe.getSignerAtIndex(i);
        signers.push(signer.toLowerCase());
      }

      // Check if user is a signer and get roles
      let userIsSigner = false;
      const userRoles: string[] = [];
      
      if (userAddress) {
        const normalizedUserAddress = userAddress.toLowerCase();
        
        // Check SAFE_SIGNER_ROLE
        const SAFE_SIGNER_ROLE = await infraSafe.SAFE_SIGNER_ROLE();
        userIsSigner = await infraSafe.hasRole(SAFE_SIGNER_ROLE, normalizedUserAddress);
        if (userIsSigner) {
          userRoles.push('SAFE_SIGNER_ROLE');
        }

        // Check DEFAULT_ADMIN_ROLE
        const DEFAULT_ADMIN_ROLE = await infraSafe.DEFAULT_ADMIN_ROLE();
        const isAdmin = await infraSafe.hasRole(DEFAULT_ADMIN_ROLE, normalizedUserAddress);
        if (isAdmin) {
          userRoles.push('DEFAULT_ADMIN_ROLE');
        }

        // Check TRUSTED_AGENT_ROLE
        const TRUSTED_AGENT_ROLE = await infraSafe.TRUSTED_AGENT_ROLE();
        const isTrustedAgent = await infraSafe.hasRole(TRUSTED_AGENT_ROLE, normalizedUserAddress);
        if (isTrustedAgent) {
          userRoles.push('TRUSTED_AGENT_ROLE');
        }
      }

      const status: WalletStatus = {
        address: walletAddress.toLowerCase(),
        threshold: Number(threshold),
        signerCount: Number(signerCount),
        signers,
        userIsSigner,
        userRoles,
        nonce: Number(nonce),
        balance: ethers.formatEther(balance),
      };

      logger.contract('Wallet status retrieved', { 
        walletAddress, 
        userAddress, 
        threshold: status.threshold,
        signerCount: status.signerCount,
        userIsSigner 
      });

      return status;
    } catch (error) {
      logger.error('Failed to get wallet status', { 
        walletAddress, 
        userAddress,
        error: error instanceof Error ? error.message : error 
      });
      throw new ContractError('Failed to get wallet status', 'WALLET_STATUS_FAILED', walletAddress);
    }
  }

  /**
   * Verify user is a signer for the wallet
   */
  async verifyUserIsSigner(walletAddress: string, userAddress: string): Promise<boolean> {
    try {
      const infraSafe = await this.getContract('InfraSafe');
      const SAFE_SIGNER_ROLE = await infraSafe.SAFE_SIGNER_ROLE();
      
      const isSigner = await infraSafe.hasRole(SAFE_SIGNER_ROLE, userAddress.toLowerCase());
      
      logger.contract('User signer verification', { 
        walletAddress, 
        userAddress, 
        isSigner 
      });
      
      return isSigner;
    } catch (error) {
      logger.error('Failed to verify user is signer', { 
        walletAddress, 
        userAddress,
        error: error instanceof Error ? error.message : error 
      });
      return false;
    }
  }

  /**
   * Get transaction hash for a transaction
   */
  async getTransactionHash(
    walletAddress: string,
    to: string,
    value: string,
    data: string,
    nonce: number
  ): Promise<string> {
    try {
      const infraSafe = await this.getContract('InfraSafe');
      const txHash = await infraSafe.getTransactionHash(to, value, data, nonce);
      
      logger.contract('Transaction hash generated', { 
        walletAddress, 
        to, 
        value, 
        nonce, 
        txHash 
      });
      
      return txHash;
    } catch (error) {
      logger.error('Failed to get transaction hash', { 
        walletAddress, 
        to, 
        value, 
        nonce,
        error: error instanceof Error ? error.message : error 
      });
      throw new ContractError('Failed to get transaction hash', 'TX_HASH_FAILED', walletAddress);
    }
  }

  /**
   * Execute a multisig transaction
   */
  async executeTransaction(
    walletAddress: string,
    to: string,
    value: string,
    data: string,
    signatures: string[]
  ): Promise<string> {
    try {
      if (!this.signer) {
        throw new ContractError('No signer available for transaction execution', 'NO_SIGNER');
      }

      const infraSafe = await this.getContractWithSigner('InfraSafe');
      
      // Execute the transaction
      const tx = await infraSafe.executeTransaction(to, value, data, signatures);
      const receipt = await tx.wait();
      
      logger.contract('Transaction executed', { 
        walletAddress, 
        to, 
        value, 
        txHash: receipt.hash,
        blockNumber: receipt.blockNumber,
        gasUsed: receipt.gasUsed?.toString()
      });
      
      return receipt.hash;
    } catch (error) {
      logger.error('Failed to execute transaction', { 
        walletAddress, 
        to, 
        value,
        error: error instanceof Error ? error.message : error 
      });
      throw new ContractError('Failed to execute transaction', 'TX_EXECUTION_FAILED', walletAddress);
    }
  }

  /**
   * Simulate a transaction using staticCall
   */
  async simulateTransaction(
    walletAddress: string,
    to: string,
    value: string,
    data: string,
    signatures: string[]
  ): Promise<{ success: boolean; returnData?: string; error?: string }> {
    try {
      const infraSafe = await this.getContract('InfraSafe');
      
      // Use staticCall to simulate the transaction
      const result = await infraSafe.executeTransaction.staticCall(to, value, data, signatures);
      
      logger.contract('Transaction simulated', { 
        walletAddress, 
        to, 
        value, 
        success: result 
      });
      
      return { success: result };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      
      logger.contract('Transaction simulation failed', { 
        walletAddress, 
        to, 
        value,
        error: errorMessage 
      });
      
      return { success: false, error: errorMessage };
    }
  }

  /**
   * Call a function on the fallback handler
   */
  async callFallbackHandler(
    walletAddress: string,
    functionSelector: string,
    data: string
  ): Promise<any> {
    try {
      const calldata = functionSelector + data.slice(2); // Remove 0x from data
      
      const result = await this.provider.call({
        to: walletAddress,
        data: calldata
      });
      
      logger.contract('Fallback handler called', { 
        walletAddress, 
        functionSelector, 
        result 
      });
      
      return result;
    } catch (error) {
      logger.error('Failed to call fallback handler', { 
        walletAddress, 
        functionSelector,
        error: error instanceof Error ? error.message : error 
      });
      throw new ContractError('Failed to call fallback handler', 'FALLBACK_CALL_FAILED', walletAddress);
    }
  }

  /**
   * Get contract events
   */
  async getEvents(
    contractName: string,
    eventName: string,
    fromBlock: number = 0,
    toBlock: number | string = 'latest'
  ): Promise<any[]> {
    try {
      const contract = await this.getContract(contractName);
      const filter = contract.filters[eventName];
      
      if (!filter) {
        throw new ContractError(`Event '${eventName}' not found on contract '${contractName}'`, 'EVENT_NOT_FOUND');
      }
      
      const events = await contract.queryFilter(filter(), fromBlock, toBlock);
      
      logger.contract('Events retrieved', { 
        contractName, 
        eventName, 
        fromBlock, 
        toBlock, 
        eventCount: events.length 
      });
      
      return events;
    } catch (error) {
      logger.error('Failed to get events', { 
        contractName, 
        eventName, 
        fromBlock, 
        toBlock,
        error: error instanceof Error ? error.message : error 
      });
      throw new ContractError('Failed to get events', 'EVENT_QUERY_FAILED');
    }
  }

  /**
   * Get network information
   */
  async getNetworkInfo(): Promise<{
    name: string;
    chainId: number;
    blockNumber: number;
  }> {
    try {
      const [network, blockNumber] = await Promise.all([
        this.provider.getNetwork(),
        this.provider.getBlockNumber()
      ]);
      
      return {
        name: network.name,
        chainId: Number(network.chainId),
        blockNumber
      };
    } catch (error) {
      logger.error('Failed to get network info', { error: error instanceof Error ? error.message : error });
      throw new ContractError('Failed to get network info', 'NETWORK_INFO_FAILED');
    }
  }

  /**
   * Check if contracts are deployed and accessible
   */
  async healthCheck(): Promise<{
    provider: boolean;
    contracts: { [name: string]: boolean };
  }> {
    const health = {
      provider: false,
      contracts: {} as { [name: string]: boolean }
    };

    try {
      // Check provider
      await this.provider.getBlockNumber();
      health.provider = true;
    } catch (error) {
      logger.error('Provider health check failed', { error: error instanceof Error ? error.message : error });
    }

    try {
      // Check contracts
      await this.loadContractRegistry();
      
      for (const contractName of Object.keys(this.contractRegistry)) {
        try {
          const contract = await this.getContract(contractName);
          await contract.getAddress(); // Simple check to ensure contract exists
          health.contracts[contractName] = true;
        } catch (error) {
          logger.error(`Contract ${contractName} health check failed`, { error: error instanceof Error ? error.message : error });
          health.contracts[contractName] = false;
        }
      }
    } catch (error) {
      logger.error('Contract health check failed', { error: error instanceof Error ? error.message : error });
    }

    return health;
  }
}

export const contractService = new ContractService();
