#!/usr/bin/env node

/**
 * InfraSafe WebAuthn Server Entry Point
 * 
 * This is the main entry point for the InfraSafe WebAuthn authentication server.
 * It provides passwordless authentication using WebAuthn and integrates with
 * InfraSafe smart contracts for multisig wallet management.
 */

import webAuthnServer from './src/app';
import { logger } from './src/utils/logger';
import { config } from './src/utils/config';

// Display startup banner
console.log(`
██╗███╗   ██╗███████╗██████╗  █████╗ ███████╗ █████╗ ███████╗███████╗
██║████╗  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝
██║██╔██╗ ██║█████╗  ██████╔╝███████║███████╗███████║█████╗  █████╗  
██║██║╚██╗██║██╔══╝  ██╔══██╗██╔══██║╚════██║██╔══██║██╔══╝  ██╔══╝  
██║██║ ╚████║██║     ██║  ██║██║  ██║███████║██║  ██║██║     ███████╗
╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝
                                                                      
🔐 WebAuthn Authentication Server v1.0.0
🏗️  Modern Multisig Wallet Authentication
`);

async function main() {
  try {
    logger.info('Starting InfraSafe WebAuthn Server...');
    
    // Validate configuration
    logger.info('Validating configuration...');
    if (!config.jwtSecret) {
      throw new Error('JWT_SECRET environment variable is required');
    }
    if (!config.cookieSecret) {
      throw new Error('COOKIE_SECRET environment variable is required');
    }
    if (!config.ethRpcUrl) {
      throw new Error('ETH_RPC_URL environment variable is required');
    }
    
    logger.info('Configuration validated successfully');
    
    // Start the server
    await webAuthnServer.start();
    
    logger.info('🎉 InfraSafe WebAuthn Server started successfully!');
    logger.info('💡 Ready to accept WebAuthn registrations and authentications');
    
  } catch (error) {
    logger.error('❌ Failed to start InfraSafe WebAuthn Server:', error);
    process.exit(1);
  }
}

// Handle process signals
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully...');
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully...');
});

// Start the application
main();
