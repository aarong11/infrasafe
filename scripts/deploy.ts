import { ethers } from "hardhat";
import "@openzeppelin/hardhat-upgrades";
import { writeFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";

// Import upgrades from hre
const hre = require("hardhat");

interface DeploymentData {
  [contractName: string]: {
    address: string;
    abi: any[];
    signatures: string[];
    implementationAddress?: string;
    proxyAdminAddress?: string;
  };
}

/**
 * Deployment script for InfraSafe contracts
 * 
 * This script:
 * 1. Deploys the InfraSafe proxy contract using OpenZeppelin upgrades
 * 2. Deploys the FallbackHandler contract
 * 3. Initializes InfraSafe with default signers and threshold
 * 4. Generates deployment metadata with ABIs and function signatures
 * 5. Saves metadata to deployments.json for the HTTP server
 */
async function main() {
  console.log("🚀 Starting InfraSafe deployment...");
  
  const [deployer] = await ethers.getSigners();
  console.log("📝 Deploying with account:", deployer.address);
  console.log("💰 Account balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)), "ETH");

  const deploymentData: DeploymentData = {};

  try {
    // Deploy FallbackHandler first
    console.log("\n📦 Deploying FallbackHandler...");
    const FallbackHandler = await ethers.getContractFactory("FallbackHandler");
    const fallbackHandler = await FallbackHandler.deploy(deployer.address);
    await fallbackHandler.waitForDeployment();
    
    const fallbackHandlerAddress = await fallbackHandler.getAddress();
    console.log("✅ FallbackHandler deployed to:", fallbackHandlerAddress);

    // Deploy InfraSafe using upgrades pattern
    console.log("\n📦 Deploying InfraSafe (Upgradeable)...");
    const InfraSafe = await ethers.getContractFactory("InfraSafe");
    
    // Default signers (you can modify these)
    const defaultSigners = [
      deployer.address,
      // Add more default signers here if needed
    ];
    
    const defaultThreshold = 1; // Require 1 signature for testing
    const admin = deployer.address;

    const infraSafe = await hre.upgrades.deployProxy(
      InfraSafe,
      [defaultSigners, defaultThreshold, admin],
      { 
        initializer: "initialize",
        kind: "uups"
      }
    );
    
    await infraSafe.waitForDeployment();
    const infraSafeAddress = await infraSafe.getAddress();
    
    console.log("✅ InfraSafe proxy deployed to:", infraSafeAddress);

    // Get implementation and proxy admin addresses
    const implementationAddress = await hre.upgrades.erc1967.getImplementationAddress(infraSafeAddress);
    const proxyAdminAddress = await hre.upgrades.erc1967.getAdminAddress(infraSafeAddress);
    
    console.log("📋 Implementation address:", implementationAddress);
    console.log("📋 Proxy admin address:", proxyAdminAddress);

    // Set fallback handler
    console.log("\n🔗 Setting fallback handler...");
    const setFallbackTx = await infraSafe.setFallbackHandler(fallbackHandlerAddress);
    await setFallbackTx.wait();
    console.log("✅ Fallback handler set successfully");

    // Generate function signatures for both contracts
    const infraSafeSignatures = generateFunctionSignatures(InfraSafe.interface);
    const fallbackHandlerSignatures = generateFunctionSignatures(FallbackHandler.interface);

    // Store deployment data
    deploymentData["InfraSafe"] = {
      address: infraSafeAddress,
      abi: JSON.parse(InfraSafe.interface.formatJson()),
      signatures: infraSafeSignatures,
      implementationAddress,
      proxyAdminAddress,
    };

    deploymentData["FallbackHandler"] = {
      address: fallbackHandlerAddress,
      abi: JSON.parse(FallbackHandler.interface.formatJson()),
      signatures: fallbackHandlerSignatures,
    };

    // Save deployment data
    const deploymentsDir = join(__dirname, "../deployments");
    if (!existsSync(deploymentsDir)) {
      mkdirSync(deploymentsDir, { recursive: true });
    }

    const deploymentFile = join(deploymentsDir, "deployments.json");
    writeFileSync(deploymentFile, JSON.stringify(deploymentData, null, 2));

    console.log("\n📄 Deployment metadata saved to:", deploymentFile);
    console.log("\n🎉 Deployment completed successfully!");
    
    // Display summary
    console.log("\n📊 DEPLOYMENT SUMMARY");
    console.log("═══════════════════════");
    console.log("InfraSafe Proxy:", infraSafeAddress);
    console.log("InfraSafe Implementation:", implementationAddress);
    console.log("FallbackHandler:", fallbackHandlerAddress);
    console.log("Default Signers:", defaultSigners);
    console.log("Threshold:", defaultThreshold);
    console.log("Admin:", admin);
    console.log("\n🌐 Start the ABI server with: npm run serve");

  } catch (error) {
    console.error("❌ Deployment failed:", error);
    process.exit(1);
  }
}

/**
 * Generate function signatures from contract interface
 */
function generateFunctionSignatures(contractInterface: any): string[] {
  const signatures: string[] = [];
  
  for (const fragment of contractInterface.fragments) {
    if (fragment.type === "function") {
      signatures.push(fragment.format("sighash"));
    }
  }
  
  return signatures.sort();
}

// Handle script execution
if (require.main === module) {
  main()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}
