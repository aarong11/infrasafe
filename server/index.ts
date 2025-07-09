import express from "express";
import cors from "cors";
import { readFileSync, existsSync } from "fs";
import { join } from "path";

/**
 * InfraSafe ABI Metadata HTTP Server
 * 
 * Provides REST API endpoints for contract metadata including:
 * - Contract addresses
 * - ABI definitions
 * - Function signatures
 * - Deployment information
 * 
 * Endpoints:
 * - GET /contracts - All contract metadata
 * - GET /contracts/:name - Specific contract metadata
 * - GET /health - Health check
 * - GET /version - API version
 */

const app = express();
const PORT = process.env.ABI_SERVER_PORT || 5656;

// Middleware
app.use(cors());
app.use(express.json());

// Request logging middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// Load deployment data
function loadDeploymentData() {
  const deploymentFile = join(__dirname, "../deployments/deployments.json");
  
  if (!existsSync(deploymentFile)) {
    console.warn("⚠️  Deployment file not found. Run deployment script first.");
    return {};
  }
  
  try {
    return JSON.parse(readFileSync(deploymentFile, "utf8"));
  } catch (error) {
    console.error("❌ Failed to load deployment data:", error);
    return {};
  }
}

// Cache deployment data (reload every 5 minutes)
let deploymentData: any = {};
let lastLoaded = 0;
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

function getDeploymentData() {
  const now = Date.now();
  if (now - lastLoaded > CACHE_DURATION) {
    deploymentData = loadDeploymentData();
    lastLoaded = now;
  }
  return deploymentData;
}

// Routes

/**
 * Health check endpoint
 */
app.get("/health", (req, res) => {
  const data = getDeploymentData();
  const contractCount = Object.keys(data).length;
  
  res.json({
    status: "healthy",
    timestamp: new Date().toISOString(),
    contractsLoaded: contractCount,
    version: "1.0.0"
  });
});

/**
 * API version endpoint
 */
app.get("/version", (req, res) => {
  res.json({
    apiVersion: "1.0.0",
    nodeVersion: process.version,
    platform: process.platform
  });
});

/**
 * Get all contracts metadata
 */
app.get("/contracts", (req, res) => {
  try {
    const data = getDeploymentData();
    
    if (Object.keys(data).length === 0) {
      return res.status(404).json({
        error: "No contracts found",
        message: "Deploy contracts first using: npm run deploy"
      });
    }
    
    res.json(data);
  } catch (error) {
    console.error("Error fetching contracts:", error);
    res.status(500).json({
      error: "Internal server error",
      message: "Failed to load contract data"
    });
  }
});

/**
 * Get specific contract metadata
 */
app.get("/contracts/:name", (req, res) => {
  try {
    const { name } = req.params;
    const data = getDeploymentData();
    
    if (!data[name]) {
      return res.status(404).json({
        error: "Contract not found",
        message: `Contract '${name}' not found in deployment data`,
        availableContracts: Object.keys(data)
      });
    }
    
    res.json({
      name,
      ...data[name]
    });
  } catch (error) {
    console.error("Error fetching contract:", error);
    res.status(500).json({
      error: "Internal server error",
      message: "Failed to load contract data"
    });
  }
});

/**
 * Get contract addresses only
 */
app.get("/addresses", (req, res) => {
  try {
    const data = getDeploymentData();
    const addresses = Object.entries(data).reduce((acc, [name, contract]: [string, any]) => {
      acc[name] = {
        address: contract.address,
        implementationAddress: contract.implementationAddress,
        proxyAdminAddress: contract.proxyAdminAddress
      };
      return acc;
    }, {} as any);
    
    res.json(addresses);
  } catch (error) {
    console.error("Error fetching addresses:", error);
    res.status(500).json({
      error: "Internal server error",
      message: "Failed to load contract addresses"
    });
  }
});

/**
 * Get function signatures for a contract
 */
app.get("/contracts/:name/signatures", (req, res) => {
  try {
    const { name } = req.params;
    const data = getDeploymentData();
    
    if (!data[name]) {
      return res.status(404).json({
        error: "Contract not found",
        message: `Contract '${name}' not found in deployment data`
      });
    }
    
    res.json({
      contract: name,
      signatures: data[name].signatures || []
    });
  } catch (error) {
    console.error("Error fetching signatures:", error);
    res.status(500).json({
      error: "Internal server error",
      message: "Failed to load contract signatures"
    });
  }
});

/**
 * Get ABI for a contract
 */
app.get("/contracts/:name/abi", (req, res) => {
  try {
    const { name } = req.params;
    const data = getDeploymentData();
    
    if (!data[name]) {
      return res.status(404).json({
        error: "Contract not found",
        message: `Contract '${name}' not found in deployment data`
      });
    }
    
    res.json({
      contract: name,
      abi: data[name].abi || []
    });
  } catch (error) {
    console.error("Error fetching ABI:", error);
    res.status(500).json({
      error: "Internal server error",
      message: "Failed to load contract ABI"
    });
  }
});

/**
 * Reload deployment data endpoint (useful for development)
 */
app.post("/reload", (req, res) => {
  try {
    deploymentData = loadDeploymentData();
    lastLoaded = Date.now();
    
    res.json({
      message: "Deployment data reloaded successfully",
      contractsLoaded: Object.keys(deploymentData).length,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error("Error reloading data:", error);
    res.status(500).json({
      error: "Failed to reload deployment data",
      message: error instanceof Error ? error.message : "Unknown error"
    });
  }
});

// 404 handler
app.use("*", (req, res) => {
  res.status(404).json({
    error: "Not found",
    message: `Route ${req.method} ${req.originalUrl} not found`,
    availableEndpoints: [
      "GET /health",
      "GET /version", 
      "GET /contracts",
      "GET /contracts/:name",
      "GET /contracts/:name/abi",
      "GET /contracts/:name/signatures",
      "GET /addresses",
      "POST /reload"
    ]
  });
});

// Error handler
app.use((error: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error("Unhandled error:", error);
  res.status(500).json({
    error: "Internal server error",
    message: "An unexpected error occurred"
  });
});

// Start server
function startServer() {
  // Initial data load
  deploymentData = loadDeploymentData();
  lastLoaded = Date.now();
  
  app.listen(PORT, () => {
    console.log("\n🌐 InfraSafe ABI Metadata Server");
    console.log("═══════════════════════════════════");
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📦 Contracts loaded: ${Object.keys(deploymentData).length}`);
    console.log("\n📋 Available endpoints:");
    console.log(`   • GET  http://localhost:${PORT}/health`);
    console.log(`   • GET  http://localhost:${PORT}/contracts`);
    console.log(`   • GET  http://localhost:${PORT}/contracts/{name}`);
    console.log(`   • GET  http://localhost:${PORT}/contracts/{name}/abi`);
    console.log(`   • GET  http://localhost:${PORT}/addresses`);
    console.log(`   • POST http://localhost:${PORT}/reload`);
    
    if (Object.keys(deploymentData).length === 0) {
      console.log("\n⚠️  No contracts found. Deploy first with: npm run deploy");
    } else {
      console.log("\n✅ Available contracts:");
      Object.entries(deploymentData).forEach(([name, contract]: [string, any]) => {
        console.log(`   • ${name}: ${contract.address}`);
      });
    }
    
    console.log("\n");
  });
}

// Handle graceful shutdown
process.on("SIGINT", () => {
  console.log("\n🛑 Server shutting down gracefully...");
  process.exit(0);
});

process.on("SIGTERM", () => {
  console.log("\n🛑 Server shutting down gracefully...");
  process.exit(0);
});

// Start the server
if (require.main === module) {
  startServer();
}

export default app;
