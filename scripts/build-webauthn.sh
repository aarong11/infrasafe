#!/bin/bash

# Build script for WebAuthn server
set -e

echo "🏗️  Building WebAuthn Server..."

# Clean previous build
echo "🧹 Cleaning previous build..."
rm -rf dist/webauthn-server

# Build TypeScript
echo "📦 Compiling TypeScript..."
npx tsc -p webauthn-server/tsconfig.json

# Copy non-TS files
echo "📋 Copying configuration files..."
cp webauthn-server/.env.example dist/webauthn-server/ 2>/dev/null || true

echo "✅ WebAuthn Server build complete!"
echo "📁 Output: dist/webauthn-server/"
echo "🚀 Run with: node dist/webauthn-server/index.js"
