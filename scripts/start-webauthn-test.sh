#!/bin/bash

# Load test environment variables (excluding comments)
export $(cat .env.test | grep -v '^#' | xargs)

# Start the WebAuthn server
npm run webauthn-server
