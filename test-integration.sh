#!/bin/bash

# Integration test script for InfraSafe system
# Tests the complete deployment and ABI server functionality

set -e

echo "🧪 InfraSafe Integration Test"
echo "============================="

INFRASAFE_URL="http://localhost:5656"
MAX_WAIT=120
WAIT_INTERVAL=5

# Function to wait for service
wait_for_service() {
    local url=$1
    local service_name=$2
    local elapsed=0
    
    echo "⏳ Waiting for $service_name to be ready..."
    
    while [ $elapsed -lt $MAX_WAIT ]; do
        if curl -sf "$url/health" > /dev/null 2>&1; then
            echo "✅ $service_name is ready!"
            return 0
        fi
        
        echo "   Waiting... ($elapsed/${MAX_WAIT}s)"
        sleep $WAIT_INTERVAL
        elapsed=$((elapsed + WAIT_INTERVAL))
    done
    
    echo "❌ $service_name failed to start within ${MAX_WAIT}s"
    return 1
}

# Function to test API endpoints
test_endpoints() {
    echo "🔍 Testing API endpoints..."
    
    # Test health endpoint
    echo "  Testing /health..."
    if curl -sf "$INFRASAFE_URL/health" | jq -e '.status == "healthy"' > /dev/null; then
        echo "  ✅ Health check passed"
    else
        echo "  ❌ Health check failed"
        return 1
    fi
    
    # Test contracts endpoint
    echo "  Testing /contracts..."
    if curl -sf "$INFRASAFE_URL/contracts" | jq -e 'has("InfraSafe")' > /dev/null; then
        echo "  ✅ Contracts endpoint working"
    else
        echo "  ❌ Contracts endpoint failed"
        return 1
    fi
    
    # Test specific contract endpoint
    echo "  Testing /contracts/InfraSafe..."
    if curl -sf "$INFRASAFE_URL/contracts/InfraSafe" | jq -e 'has("address")' > /dev/null; then
        echo "  ✅ InfraSafe contract data available"
    else
        echo "  ❌ InfraSafe contract data not found"
        return 1
    fi
    
    # Test signatures endpoint
    echo "  Testing /contracts/InfraSafe/signatures..."
    if curl -sf "$INFRASAFE_URL/contracts/InfraSafe/signatures" | jq -e '.signatures | length > 0' > /dev/null; then
        echo "  ✅ Function signatures available"
    else
        echo "  ❌ Function signatures not found"
        return 1
    fi
    
    echo "✅ All API endpoints working correctly!"
}

# Function to display contract info
show_contract_info() {
    echo "📋 Contract Information:"
    echo "======================="
    
    local contracts_data=$(curl -sf "$INFRASAFE_URL/contracts")
    
    echo "InfraSafe Contract:"
    echo "  Address: $(echo "$contracts_data" | jq -r '.InfraSafe.address')"
    echo "  Implementation: $(echo "$contracts_data" | jq -r '.InfraSafe.implementationAddress')"
    echo "  Functions: $(echo "$contracts_data" | jq -r '.InfraSafe.signatures | length')"
    
    echo ""
    echo "FallbackHandler Contract:"
    echo "  Address: $(echo "$contracts_data" | jq -r '.FallbackHandler.address')"
    echo "  Functions: $(echo "$contracts_data" | jq -r '.FallbackHandler.signatures | length')"
}

# Main test execution
main() {
    echo "Starting InfraSafe container..."
    docker-compose up -d infrasafe
    
    # Wait for service to be ready
    if wait_for_service "$INFRASAFE_URL" "InfraSafe ABI Server"; then
        # Run API tests
        if test_endpoints; then
            # Show contract information
            show_contract_info
            echo ""
            echo "🎉 Integration test completed successfully!"
            echo "🌐 InfraSafe ABI Server is available at: $INFRASAFE_URL"
            return 0
        else
            echo "❌ API tests failed"
            return 1
        fi
    else
        echo "❌ Service failed to start"
        return 1
    fi
}

# Check dependencies
if ! command -v jq &> /dev/null; then
    echo "❌ jq is required but not installed. Please install jq first."
    exit 1
fi

if ! command -v curl &> /dev/null; then
    echo "❌ curl is required but not installed. Please install curl first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ docker-compose is required but not installed. Please install docker-compose first."
    exit 1
fi

# Run main function
main
