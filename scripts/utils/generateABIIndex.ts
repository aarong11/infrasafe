import { readFileSync, writeFileSync } from "fs";
import { join } from "path";

/**
 * Utility to generate ABI index from deployment data
 * This can be used to create additional metadata or documentation
 */

interface ContractMetadata {
  address: string;
  abi: any[];
  signatures: string[];
  implementationAddress?: string;
  proxyAdminAddress?: string;
}

interface DeploymentData {
  [contractName: string]: ContractMetadata;
}

/**
 * Generate a human-readable ABI index
 */
export function generateABIIndex(deploymentPath: string): string {
  const deploymentData: DeploymentData = JSON.parse(
    readFileSync(deploymentPath, "utf8")
  );

  let output = "# InfraSafe Contract ABI Index\n\n";
  output += `Generated on: ${new Date().toISOString()}\n\n`;

  for (const [contractName, metadata] of Object.entries(deploymentData)) {
    output += `## ${contractName}\n\n`;
    output += `**Address:** \`${metadata.address}\`\n\n`;
    
    if (metadata.implementationAddress) {
      output += `**Implementation:** \`${metadata.implementationAddress}\`\n\n`;
    }
    
    if (metadata.proxyAdminAddress) {
      output += `**Proxy Admin:** \`${metadata.proxyAdminAddress}\`\n\n`;
    }

    output += "### Function Signatures\n\n";
    metadata.signatures.forEach(sig => {
      output += `- \`${sig}\`\n`;
    });
    
    output += "\n### Full ABI\n\n";
    output += "```json\n";
    output += JSON.stringify(metadata.abi, null, 2);
    output += "\n```\n\n";
  }

  return output;
}

/**
 * Generate TypeScript interfaces from ABI
 */
export function generateTypeScriptInterfaces(deploymentPath: string): string {
  const deploymentData: DeploymentData = JSON.parse(
    readFileSync(deploymentPath, "utf8")
  );

  let output = "// Auto-generated TypeScript interfaces for InfraSafe contracts\n\n";

  for (const [contractName, metadata] of Object.entries(deploymentData)) {
    output += `export interface ${contractName}Methods {\n`;
    
    // Extract function names from ABI
    const functions = metadata.abi
      .filter((item: any) => item.type === "function")
      .map((item: any) => item.name);
    
    functions.forEach((funcName: string) => {
      output += `  ${funcName}: any; // TODO: Add proper typing\n`;
    });
    
    output += "}\n\n";

    output += `export interface ${contractName}Events {\n`;
    
    // Extract event names from ABI
    const events = metadata.abi
      .filter((item: any) => item.type === "event")
      .map((item: any) => item.name);
    
    events.forEach((eventName: string) => {
      output += `  ${eventName}: any; // TODO: Add proper typing\n`;
    });
    
    output += "}\n\n";
  }

  return output;
}

/**
 * Main function to generate all index files
 */
export async function generateAllIndexes(deploymentsDir: string): Promise<void> {
  const deploymentFile = join(deploymentsDir, "deployments.json");
  
  try {
    // Generate markdown documentation
    const markdownIndex = generateABIIndex(deploymentFile);
    writeFileSync(join(deploymentsDir, "ABI_INDEX.md"), markdownIndex);
    
    // Generate TypeScript interfaces
    const tsInterfaces = generateTypeScriptInterfaces(deploymentFile);
    writeFileSync(join(deploymentsDir, "interfaces.ts"), tsInterfaces);
    
    console.log("✅ Generated ABI documentation files");
  } catch (error) {
    console.error("❌ Failed to generate ABI indexes:", error);
  }
}

// CLI usage
if (require.main === module) {
  const deploymentsDir = join(__dirname, "../deployments");
  generateAllIndexes(deploymentsDir);
}
