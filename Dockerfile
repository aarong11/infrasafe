# InfraSafe Smart Contract System Dockerfile
FROM node:20-alpine

# Install system dependencies including netcat for service checks
RUN apk add --no-cache git python3 make g++ curl netcat-openbsd

# Set working directory
WORKDIR /app

# Copy package files
COPY package.json yarn.lock tsconfig.json ./

# Install dependencies
RUN yarn install

# Copy source code
COPY . .

# Compile contracts
RUN yarn compile

# Create deployments directory
RUN mkdir -p deployments

# Make startup script executable
RUN chmod +x /app/start.sh

# Expose the ABI server port
EXPOSE 5656

# Expose Hardhat node port
EXPOSE 8545

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=90s --retries=3 \
  CMD curl -f http://localhost:5656/health || exit 1

# Use the startup script
CMD ["/app/start.sh"]
