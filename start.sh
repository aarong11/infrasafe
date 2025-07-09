#!/bin/sh

set -e

echo "🚀 InfraSafe Container Starting..."

# Function to wait for a service to be ready
wait_for_service() {
    local host=$1
    local port=$2
    local service_name=$3
    local max_attempts=30
    local attempt=1
    
    echo "⏳ Waiting for $service_name to be ready at $host:$port..."
    
    while [ $attempt -le $max_attempts ]; do
        if nc -z "$host" "$port" 2>/dev/null; then
            echo "✅ $service_name is ready!"
            return 0
        fi
        
        echo "   Attempt $attempt/$max_attempts - $service_name not ready yet..."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    echo "❌ $service_name failed to become ready after $max_attempts attempts"
    return 1
}

# Function to check if deployment exists and is valid
check_deployment() {
    if [ -f "/app/deployments/deployments.json" ]; then
        # Check if file contains actual deployment data (not just placeholder)
        if grep -q "InfraSafe" "/app/deployments/deployments.json" 2>/dev/null; then
            echo "✅ Found existing deployment data"
            return 0
        fi
    fi
    echo "⚠️  No valid deployment data found"
    return 1
}

# Start Hardhat node in background
echo "🔗 Starting Hardhat node..."
yarn hardhat node --hostname 0.0.0.0 --port 8545 &
HARDHAT_PID=$!

# Wait for Hardhat node to be ready
sleep 10

# Wait for node to accept connections
wait_for_service "localhost" "8545" "Hardhat node"

# Deploy contracts if not already deployed
if ! check_deployment; then
    echo "📦 Deploying contracts..."
    if yarn deploy; then
        echo "✅ Contracts deployed successfully"
    else
        echo "❌ Contract deployment failed"
        exit 1
    fi
else
    echo "📋 Using existing deployment"
fi

# Start ABI metadata server
echo "🌐 Starting ABI metadata server on port 5656..."
exec yarn serve
