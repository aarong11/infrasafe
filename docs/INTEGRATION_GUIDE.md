# InfraSafe WebAuthn Integration Guide

## Overview

This guide provides step-by-step instructions for integrating the InfraSafe WebAuthn API into your application. The integration enables passwordless authentication for Ethereum multisig wallets using biometrics and hardware security keys.

## Prerequisites

- Modern web browser with WebAuthn support
- HTTPS connection (required for WebAuthn in production)
- Valid Ethereum wallet address
- Basic knowledge of JavaScript/TypeScript and async/await

## Browser Compatibility

WebAuthn is supported in:
- Chrome 67+
- Firefox 60+
- Safari 14+
- Edge 18+

## Installation

### NPM Package (Recommended)

```bash
npm install @infrasafe/webauthn-client
```

### CDN

```html
<script src="https://unpkg.com/@infrasafe/webauthn-client@latest/dist/infrasafe-webauthn.min.js"></script>
```

## Quick Start

### 1. Initialize the Client

```typescript
import { InfraSafeWebAuthn } from '@infrasafe/webauthn-client';

const webauthn = new InfraSafeWebAuthn({
  apiUrl: 'https://api.infrasafe.io', // or 'http://localhost:3001' for development
  timeout: 300000, // 5 minutes
});
```

### 2. Check WebAuthn Support

```typescript
if (!webauthn.isSupported()) {
  console.error('WebAuthn is not supported in this browser');
  // Show fallback authentication method
  return;
}
```

### 3. Register a New Device

```typescript
async function registerDevice(username: string, walletAddress: string) {
  try {
    // Step 1: Get registration options
    const options = await webauthn.startRegistration({
      username,
      walletAddress,
      deviceName: 'My Device' // optional
    });

    // Step 2: Create credential using browser WebAuthn API
    const credential = await navigator.credentials.create({
      publicKey: options.options
    });

    // Step 3: Verify registration
    const result = await webauthn.finishRegistration({
      userId: options.userId,
      credential
    });

    console.log('Registration successful:', result);
    
    // Store the JWT token
    localStorage.setItem('infrasafe_token', result.session.token);
    
    return result;
  } catch (error) {
    console.error('Registration failed:', error);
    throw error;
  }
}
```

### 4. Authenticate with Existing Device

```typescript
async function authenticateUser(walletAddress: string) {
  try {
    // Step 1: Get authentication options
    const options = await webauthn.startAuthentication({
      walletAddress
    });

    if (!options.hasDevices) {
      throw new Error('No devices registered for this wallet');
    }

    // Step 2: Get credential using browser WebAuthn API
    const credential = await navigator.credentials.get({
      publicKey: options.options
    });

    // Step 3: Verify authentication
    const result = await webauthn.finishAuthentication({
      credential
    });

    console.log('Authentication successful:', result);
    
    // Store the JWT token
    localStorage.setItem('infrasafe_token', result.session.token);
    
    return result;
  } catch (error) {
    console.error('Authentication failed:', error);
    throw error;
  }
}
```

## Complete Integration Example

### React Component

```tsx
import React, { useState, useEffect } from 'react';
import { InfraSafeWebAuthn } from '@infrasafe/webauthn-client';

const AuthComponent: React.FC = () => {
  const [webauthn] = useState(() => new InfraSafeWebAuthn({
    apiUrl: process.env.REACT_APP_API_URL || 'http://localhost:3001'
  }));
  
  const [isSupported, setIsSupported] = useState(false);
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Form state
  const [username, setUsername] = useState('');
  const [walletAddress, setWalletAddress] = useState('');

  useEffect(() => {
    setIsSupported(webauthn.isSupported());
    
    // Check for existing session
    const token = localStorage.getItem('infrasafe_token');
    if (token) {
      verifySession(token);
    }
  }, []);

  const verifySession = async (token: string) => {
    try {
      webauthn.setToken(token);
      const userData = await webauthn.getCurrentUser();
      setUser(userData);
    } catch (error) {
      localStorage.removeItem('infrasafe_token');
      console.error('Session invalid:', error);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const result = await registerDevice(username, walletAddress);
      setUser(result.user);
    } catch (error: any) {
      setError(error.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const result = await authenticateUser(walletAddress);
      setUser(result.user);
    } catch (error: any) {
      setError(error.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      await webauthn.logout();
      localStorage.removeItem('infrasafe_token');
      setUser(null);
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };

  if (!isSupported) {
    return (
      <div className="error">
        <h2>WebAuthn Not Supported</h2>
        <p>Your browser does not support WebAuthn. Please use a modern browser.</p>
      </div>
    );
  }

  if (user) {
    return (
      <div className="dashboard">
        <h2>Welcome, {user.username}!</h2>
        <p>Wallet: {user.walletAddress}</p>
        <button onClick={handleLogout}>Logout</button>
      </div>
    );
  }

  return (
    <div className="auth-container">
      <h1>InfraSafe Authentication</h1>
      
      {error && (
        <div className="error">
          {error}
        </div>
      )}

      {/* Registration Form */}
      <form onSubmit={handleRegister}>
        <h2>Register New Device</h2>
        <input
          type="text"
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          required
        />
        <input
          type="text"
          placeholder="Wallet Address (0x...)"
          value={walletAddress}
          onChange={(e) => setWalletAddress(e.target.value)}
          required
        />
        <button type="submit" disabled={loading}>
          {loading ? 'Registering...' : 'Register Device'}
        </button>
      </form>

      {/* Login Form */}
      <form onSubmit={handleLogin}>
        <h2>Sign In</h2>
        <input
          type="text"
          placeholder="Wallet Address (0x...)"
          value={walletAddress}
          onChange={(e) => setWalletAddress(e.target.value)}
          required
        />
        <button type="submit" disabled={loading}>
          {loading ? 'Authenticating...' : 'Sign In'}
        </button>
      </form>
    </div>
  );
};

// Helper functions
async function registerDevice(username: string, walletAddress: string) {
  // Implementation from Quick Start section
}

async function authenticateUser(walletAddress: string) {
  // Implementation from Quick Start section
}

export default AuthComponent;
```

### Vanilla JavaScript Example

```html
<!DOCTYPE html>
<html>
<head>
    <title>InfraSafe WebAuthn Demo</title>
    <script src="https://unpkg.com/@infrasafe/webauthn-client@latest/dist/infrasafe-webauthn.min.js"></script>
</head>
<body>
    <div id="app">
        <h1>InfraSafe WebAuthn Demo</h1>
        
        <div id="auth-forms">
            <form id="register-form">
                <h2>Register Device</h2>
                <input type="text" id="reg-username" placeholder="Username" required>
                <input type="text" id="reg-wallet" placeholder="Wallet Address" required>
                <button type="submit">Register</button>
            </form>
            
            <form id="login-form">
                <h2>Sign In</h2>
                <input type="text" id="login-wallet" placeholder="Wallet Address" required>
                <button type="submit">Sign In</button>
            </form>
        </div>
        
        <div id="dashboard" style="display: none;">
            <h2>Welcome!</h2>
            <div id="user-info"></div>
            <button id="logout-btn">Logout</button>
        </div>
        
        <div id="error" style="display: none; color: red;"></div>
    </div>

    <script>
        const webauthn = new InfraSafeWebAuthn({
            apiUrl: 'http://localhost:3001'
        });

        // Check WebAuthn support
        if (!webauthn.isSupported()) {
            document.getElementById('error').style.display = 'block';
            document.getElementById('error').textContent = 'WebAuthn not supported';
        }

        // Registration form handler
        document.getElementById('register-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('reg-username').value;
            const walletAddress = document.getElementById('reg-wallet').value;
            
            try {
                showLoading(true);
                const result = await registerDevice(username, walletAddress);
                showDashboard(result.user);
            } catch (error) {
                showError(error.message);
            } finally {
                showLoading(false);
            }
        });

        // Login form handler  
        document.getElementById('login-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const walletAddress = document.getElementById('login-wallet').value;
            
            try {
                showLoading(true);
                const result = await authenticateUser(walletAddress);
                showDashboard(result.user);
            } catch (error) {
                showError(error.message);
            } finally {
                showLoading(false);
            }
        });

        // Logout handler
        document.getElementById('logout-btn').addEventListener('click', async () => {
            try {
                await webauthn.logout();
                localStorage.removeItem('infrasafe_token');
                showAuthForms();
            } catch (error) {
                console.error('Logout failed:', error);
            }
        });

        // Helper functions
        async function registerDevice(username, walletAddress) {
            const options = await webauthn.startRegistration({
                username,
                walletAddress,
                deviceName: navigator.userAgent.includes('Mobile') ? 'Mobile Device' : 'Desktop'
            });

            const credential = await navigator.credentials.create({
                publicKey: options.options
            });

            const result = await webauthn.finishRegistration({
                userId: options.userId,
                credential
            });

            localStorage.setItem('infrasafe_token', result.session.token);
            return result;
        }

        async function authenticateUser(walletAddress) {
            const options = await webauthn.startAuthentication({
                walletAddress
            });

            if (!options.hasDevices) {
                throw new Error('No devices registered for this wallet');
            }

            const credential = await navigator.credentials.get({
                publicKey: options.options
            });

            const result = await webauthn.finishAuthentication({
                credential
            });

            localStorage.setItem('infrasafe_token', result.session.token);
            return result;
        }

        function showDashboard(user) {
            document.getElementById('auth-forms').style.display = 'none';
            document.getElementById('dashboard').style.display = 'block';
            document.getElementById('user-info').innerHTML = `
                <p><strong>Username:</strong> ${user.username}</p>
                <p><strong>Wallet:</strong> ${user.walletAddress}</p>
                <p><strong>Registered:</strong> ${new Date(user.createdAt).toLocaleString()}</p>
            `;
        }

        function showAuthForms() {
            document.getElementById('auth-forms').style.display = 'block';
            document.getElementById('dashboard').style.display = 'none';
            document.getElementById('error').style.display = 'none';
        }

        function showError(message) {
            document.getElementById('error').style.display = 'block';
            document.getElementById('error').textContent = message;
        }

        function showLoading(loading) {
            const buttons = document.querySelectorAll('button');
            buttons.forEach(btn => btn.disabled = loading);
        }

        // Check for existing session on load
        window.addEventListener('load', async () => {
            const token = localStorage.getItem('infrasafe_token');
            if (token) {
                try {
                    webauthn.setToken(token);
                    const user = await webauthn.getCurrentUser();
                    showDashboard(user);
                } catch (error) {
                    localStorage.removeItem('infrasafe_token');
                    showAuthForms();
                }
            }
        });
    </script>
</body>
</html>
```

## Wallet Integration

### Transaction Signing Flow

```typescript
import { InfraSafeWallet } from '@infrasafe/webauthn-client';

class WalletManager {
  private wallet: InfraSafeWallet;

  constructor(apiUrl: string, token: string) {
    this.wallet = new InfraSafeWallet({
      apiUrl,
      token
    });
  }

  async sendTransaction(walletAddress: string, to: string, value: string, data: string) {
    try {
      // 1. Get wallet status
      const status = await this.wallet.getWalletStatus(walletAddress);
      console.log('Wallet status:', status);

      // 2. Prepare transaction
      const prepared = await this.wallet.prepareTransaction(walletAddress, {
        to,
        value,
        data,
        description: 'Test transaction'
      });

      console.log('Transaction prepared:', prepared);
      console.log('Required signatures:', prepared.requiresSignatures);

      // 3. Simulate transaction (optional)
      const simulation = await this.wallet.simulateTransaction(walletAddress, {
        to,
        value,
        data
      });

      console.log('Simulation result:', simulation);

      if (!simulation.success) {
        throw new Error(`Transaction simulation failed: ${simulation.error}`);
      }

      // 4. Get signatures (this would integrate with your signing mechanism)
      const signatures = await this.getSignatures(prepared.hash, prepared.requiresSignatures);

      // 5. Submit transaction
      const result = await this.wallet.submitTransaction(walletAddress, {
        to,
        value,
        data,
        signatures
      });

      console.log('Transaction submitted:', result);
      return result;

    } catch (error) {
      console.error('Transaction failed:', error);
      throw error;
    }
  }

  async getSignatures(hash: string, requiredCount: number): Promise<string[]> {
    // Implement your signature collection logic
    // This could involve:
    // - Hardware wallet integration
    // - Multiple user approvals
    // - Smart contract signature aggregation
    
    const signatures: string[] = [];
    
    // Example: Collect signatures from multiple signers
    for (let i = 0; i < requiredCount; i++) {
      const signature = await this.requestSignature(hash, i);
      signatures.push(signature);
    }
    
    return signatures;
  }

  private async requestSignature(hash: string, signerIndex: number): Promise<string> {
    // Implement signature request logic
    // Return hex-encoded signature
    throw new Error('Signature collection not implemented');
  }
}
```

### Error Handling

```typescript
import { WebAuthnError, AuthenticationError, ContractError } from '@infrasafe/webauthn-client';

class ErrorHandler {
  static handle(error: any): string {
    if (error instanceof WebAuthnError) {
      switch (error.code) {
        case 'USER_ALREADY_EXISTS':
          return 'A user with this wallet address already exists. Please sign in instead.';
        case 'USER_NOT_FOUND':
          return 'No user found with this wallet address. Please register first.';
        case 'DEVICE_NOT_FOUND':
          return 'No registered devices found. Please register a device first.';
        case 'INVALID_CHALLENGE':
          return 'Security challenge expired. Please try again.';
        case 'REGISTRATION_FAILED':
          return 'Device registration failed. Please try again.';
        case 'AUTHENTICATION_FAILED':
          return 'Authentication failed. Please verify your identity and try again.';
        default:
          return `WebAuthn error: ${error.message}`;
      }
    }

    if (error instanceof AuthenticationError) {
      switch (error.code) {
        case 'INVALID_TOKEN':
          return 'Your session is invalid. Please sign in again.';
        case 'TOKEN_EXPIRED':
          return 'Your session has expired. Please sign in again.';
        case 'INSUFFICIENT_PERMISSIONS':
          return 'You do not have permission to perform this action.';
        default:
          return `Authentication error: ${error.message}`;
      }
    }

    if (error instanceof ContractError) {
      switch (error.code) {
        case 'INVALID_SIGNER':
          return 'You are not authorized to sign transactions for this wallet.';
        case 'INSUFFICIENT_SIGNATURES':
          return 'Not enough signatures to execute this transaction.';
        case 'TRANSACTION_FAILED':
          return 'Transaction execution failed. Please check your parameters.';
        default:
          return `Contract error: ${error.message}`;
      }
    }

    // Handle WebAuthn browser errors
    if (error.name === 'NotAllowedError') {
      return 'Authentication was cancelled or not allowed.';
    }

    if (error.name === 'NotSupportedError') {
      return 'This authenticator is not supported.';
    }

    if (error.name === 'SecurityError') {
      return 'Security error occurred. Please ensure you are on a secure connection.';
    }

    if (error.name === 'NetworkError') {
      return 'Network error occurred. Please check your connection and try again.';
    }

    // Generic error
    return error.message || 'An unknown error occurred.';
  }
}

// Usage in your components
try {
  await registerDevice(username, walletAddress);
} catch (error) {
  const userMessage = ErrorHandler.handle(error);
  setError(userMessage);
}
```

## Production Considerations

### Security Checklist

- ✅ Use HTTPS in production
- ✅ Validate all user inputs
- ✅ Implement proper error handling
- ✅ Store JWT tokens securely
- ✅ Implement token refresh logic
- ✅ Use secure headers (CSP, HSTS, etc.)
- ✅ Validate wallet addresses
- ✅ Implement proper logging
- ✅ Monitor rate limits
- ✅ Handle offline scenarios

### Performance Optimization

```typescript
// Token refresh implementation
class TokenManager {
  private token: string | null = null;
  private refreshPromise: Promise<string> | null = null;

  async getValidToken(): Promise<string> {
    if (!this.token) {
      throw new Error('No token available');
    }

    // Check if token is about to expire
    if (this.isTokenExpiringSoon(this.token)) {
      return this.refreshToken();
    }

    return this.token;
  }

  private async refreshToken(): Promise<string> {
    // Prevent multiple simultaneous refresh requests
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    this.refreshPromise = this.performTokenRefresh();
    
    try {
      const newToken = await this.refreshPromise;
      this.token = newToken;
      localStorage.setItem('infrasafe_token', newToken);
      return newToken;
    } finally {
      this.refreshPromise = null;
    }
  }

  private async performTokenRefresh(): Promise<string> {
    const response = await fetch('/webauthn/refresh', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.token}`,
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error('Token refresh failed');
    }

    const data = await response.json();
    return data.data.token;
  }

  private isTokenExpiringSoon(token: string): boolean {
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      const expirationTime = payload.exp * 1000;
      const currentTime = Date.now();
      const fiveMinutes = 5 * 60 * 1000;
      
      return expirationTime - currentTime < fiveMinutes;
    } catch {
      return true; // Assume expired if we can't parse
    }
  }
}
```

### Deployment Configuration

```typescript
// Environment-specific configuration
const config = {
  development: {
    apiUrl: 'http://localhost:3001',
    timeout: 300000,
    retries: 3,
    logLevel: 'debug'
  },
  production: {
    apiUrl: 'https://api.infrasafe.io',
    timeout: 300000,
    retries: 1,
    logLevel: 'error'
  }
};

const webauthn = new InfraSafeWebAuthn(
  config[process.env.NODE_ENV || 'development']
);
```

## Testing

### Unit Tests

```typescript
import { InfraSafeWebAuthn } from '@infrasafe/webauthn-client';

describe('InfraSafeWebAuthn', () => {
  let webauthn: InfraSafeWebAuthn;

  beforeEach(() => {
    webauthn = new InfraSafeWebAuthn({
      apiUrl: 'http://localhost:3001'
    });
  });

  test('should detect WebAuthn support', () => {
    // Mock WebAuthn support
    Object.defineProperty(window, 'PublicKeyCredential', {
      value: function() {},
      writable: true
    });

    expect(webauthn.isSupported()).toBe(true);
  });

  test('should handle registration flow', async () => {
    // Mock fetch responses
    global.fetch = jest.fn()
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          success: true,
          data: { options: {}, userId: 'test-uuid' }
        })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          success: true,
          data: { user: {}, session: { token: 'test-token' } }
        })
      });

    // Mock navigator.credentials.create
    Object.defineProperty(navigator, 'credentials', {
      value: {
        create: jest.fn().mockResolvedValue({
          id: 'credential-id',
          response: {}
        })
      },
      writable: true
    });

    const result = await webauthn.startRegistration({
      username: 'testuser',
      walletAddress: '0x1234567890123456789012345678901234567890'
    });

    expect(result).toHaveProperty('options');
    expect(result).toHaveProperty('userId');
  });
});
```

### End-to-End Tests

```typescript
import { test, expect } from '@playwright/test';

test.describe('WebAuthn Integration', () => {
  test('should complete registration flow', async ({ page, context }) => {
    // Enable WebAuthn virtual authenticator
    const cdpSession = await context.newCDPSession(page);
    await cdpSession.send('WebAuthn.enable');
    await cdpSession.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true
      }
    });

    await page.goto('http://localhost:3000');

    // Fill registration form
    await page.fill('#reg-username', 'testuser');
    await page.fill('#reg-wallet', '0x1234567890123456789012345678901234567890');
    
    // Submit registration
    await page.click('#register-form button');
    
    // Wait for successful registration
    await expect(page.locator('#dashboard')).toBeVisible();
    await expect(page.locator('#user-info')).toContainText('testuser');
  });
});
```

## Troubleshooting

### Common Issues

1. **WebAuthn Not Supported**
   - Ensure HTTPS in production
   - Check browser compatibility
   - Verify SecureContext availability

2. **Registration Fails**
   - Check CORS configuration
   - Verify API endpoint accessibility
   - Ensure valid wallet address format

3. **Authentication Fails**
   - Verify device is registered
   - Check for expired challenges
   - Ensure proper error handling

4. **Token Issues**
   - Implement token refresh logic
   - Handle token expiration gracefully
   - Verify JWT format and claims

### Debug Mode

```typescript
const webauthn = new InfraSafeWebAuthn({
  apiUrl: 'http://localhost:3001',
  debug: true // Enable debug logging
});

// Monitor all API calls
webauthn.on('request', (url, options) => {
  console.log('API Request:', url, options);
});

webauthn.on('response', (url, response) => {
  console.log('API Response:', url, response);
});

webauthn.on('error', (error) => {
  console.error('WebAuthn Error:', error);
});
```

## Support

For additional support and documentation:

- 📖 [API Reference](https://docs.infrasafe.io/api)
- 🐛 [Report Issues](https://github.com/infrasafe/webauthn-client/issues)
- 💬 [Community Discord](https://discord.gg/infrasafe)
- 📧 [Email Support](mailto:support@infrasafe.io)

## License

MIT License - see [LICENSE](./LICENSE) file for details.
