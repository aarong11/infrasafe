import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcrypt';
import NodeCache from 'node-cache';
import { 
  User, 
  UserDevice, 
  RegistrationChallenge, 
  AuthenticationChallenge, 
  AuthSession,
  TransactionSubmission
} from '../types';
import { config } from '../utils/config';
import { logger } from '../utils/logger';

/**
 * In-memory storage service for WebAuthn credentials and user data
 * In production, this should be replaced with a proper database
 */
class StorageService {
  private cache: NodeCache;
  private users: Map<string, User>;
  private devices: Map<string, UserDevice>;
  private registrationChallenges: Map<string, RegistrationChallenge>;
  private authenticationChallenges: Map<string, AuthenticationChallenge>;
  private sessions: Map<string, AuthSession>;
  private transactions: Map<string, TransactionSubmission>;
  private usersByWallet: Map<string, string>; // walletAddress -> userId
  private usersByUsername: Map<string, string>; // username -> userId
  private devicesByUser: Map<string, string[]>; // userId -> deviceIds[]
  private cleanupTimer: NodeJS.Timeout;

  constructor() {
    this.cache = new NodeCache({
      stdTTL: config.cacheMaxAge,
      checkperiod: config.cachCheckPeriod,
    });
    
    this.users = new Map();
    this.devices = new Map();
    this.registrationChallenges = new Map();
    this.authenticationChallenges = new Map();
    this.sessions = new Map();
    this.transactions = new Map();
    this.usersByWallet = new Map();
    this.usersByUsername = new Map();
    this.devicesByUser = new Map();

    // Cleanup expired data periodically
    this.cleanupTimer = setInterval(() => this.cleanup(), 60000); // Every minute
  }

  // User operations
  async createUser(username: string, walletAddress: string): Promise<User> {
    const userId = uuidv4();
    const normalizedWallet = walletAddress.toLowerCase();
    const normalizedUsername = username.toLowerCase();

    // Check for existing user
    if (this.usersByWallet.has(normalizedWallet)) {
      throw new Error('User with this wallet address already exists');
    }
    if (this.usersByUsername.has(normalizedUsername)) {
      throw new Error('Username already taken');
    }

    const user: User = {
      id: userId,
      username,
      walletAddress: normalizedWallet,
      createdAt: new Date(),
    };

    this.users.set(userId, user);
    this.usersByWallet.set(normalizedWallet, userId);
    this.usersByUsername.set(normalizedUsername, userId);
    this.devicesByUser.set(userId, []);

    logger.info('User created', { userId, username, walletAddress: normalizedWallet });
    return user;
  }

  async getUserById(userId: string): Promise<User | null> {
    return this.users.get(userId) || null;
  }

  async getUserByWalletAddress(walletAddress: string): Promise<User | null> {
    const userId = this.usersByWallet.get(walletAddress.toLowerCase());
    return userId ? this.users.get(userId) || null : null;
  }

  async getUserByUsername(username: string): Promise<User | null> {
    const userId = this.usersByUsername.get(username.toLowerCase());
    return userId ? this.users.get(userId) || null : null;
  }

  async updateUserLastLogin(userId: string): Promise<void> {
    const user = this.users.get(userId);
    if (user) {
      user.lastLoginAt = new Date();
      this.users.set(userId, user);
    }
  }

  // Device operations
  async saveDevice(device: UserDevice): Promise<void> {
    this.devices.set(device.id, device);
    
    // Update user's device list
    const userDevices = this.devicesByUser.get(device.userId) || [];
    if (!userDevices.includes(device.id)) {
      userDevices.push(device.id);
      this.devicesByUser.set(device.userId, userDevices);
    }

    logger.info('Device saved', { deviceId: device.id, userId: device.userId });
  }

  async getDeviceById(deviceId: string): Promise<UserDevice | null> {
    return this.devices.get(deviceId) || null;
  }

  async getDevicesByUserId(userId: string): Promise<UserDevice[]> {
    const deviceIds = this.devicesByUser.get(userId) || [];
    return deviceIds.map(id => this.devices.get(id)).filter(Boolean) as UserDevice[];
  }

  async updateDeviceLastUsed(deviceId: string): Promise<void> {
    const device = this.devices.get(deviceId);
    if (device) {
      device.lastUsedAt = new Date();
      this.devices.set(deviceId, device);
    }
  }

  async removeDevice(deviceId: string): Promise<void> {
    const device = this.devices.get(deviceId);
    if (device) {
      this.devices.delete(deviceId);
      
      // Remove from user's device list
      const userDevices = this.devicesByUser.get(device.userId) || [];
      const updatedDevices = userDevices.filter(id => id !== deviceId);
      this.devicesByUser.set(device.userId, updatedDevices);
      
      logger.info('Device removed', { deviceId, userId: device.userId });
    }
  }

  // Challenge operations
  async saveRegistrationChallenge(challenge: RegistrationChallenge): Promise<void> {
    this.registrationChallenges.set(challenge.challenge, challenge);
    
    // Set expiration
    setTimeout(() => {
      this.registrationChallenges.delete(challenge.challenge);
    }, challenge.expiresAt.getTime() - Date.now());
  }

  async getRegistrationChallenge(challenge: string): Promise<RegistrationChallenge | null> {
    const challengeData = this.registrationChallenges.get(challenge);
    if (challengeData && challengeData.expiresAt > new Date()) {
      return challengeData;
    }
    
    // Remove expired challenge
    if (challengeData) {
      this.registrationChallenges.delete(challenge);
    }
    
    return null;
  }

  async removeRegistrationChallenge(challenge: string): Promise<void> {
    this.registrationChallenges.delete(challenge);
  }

  async saveAuthenticationChallenge(challenge: AuthenticationChallenge): Promise<void> {
    this.authenticationChallenges.set(challenge.challenge, challenge);
    
    // Set expiration
    setTimeout(() => {
      this.authenticationChallenges.delete(challenge.challenge);
    }, challenge.expiresAt.getTime() - Date.now());
  }

  async getAuthenticationChallenge(challenge: string): Promise<AuthenticationChallenge | null> {
    const challengeData = this.authenticationChallenges.get(challenge);
    if (challengeData && challengeData.expiresAt > new Date()) {
      return challengeData;
    }
    
    // Remove expired challenge
    if (challengeData) {
      this.authenticationChallenges.delete(challenge);
    }
    
    return null;
  }

  async removeAuthenticationChallenge(challenge: string): Promise<void> {
    this.authenticationChallenges.delete(challenge);
  }

  // Session operations
  async createSession(session: AuthSession): Promise<void> {
    this.sessions.set(session.sessionId, session);
    
    // Set expiration
    setTimeout(() => {
      this.sessions.delete(session.sessionId);
    }, session.expiresAt.getTime() - Date.now());

    logger.auth('Session created', { sessionId: session.sessionId, userId: session.userId });
  }

  async getSession(sessionId: string): Promise<AuthSession | null> {
    const session = this.sessions.get(sessionId);
    if (session && session.expiresAt > new Date()) {
      return session;
    }
    
    // Remove expired session
    if (session) {
      this.sessions.delete(sessionId);
    }
    
    return null;
  }

  async removeSession(sessionId: string): Promise<void> {
    this.sessions.delete(sessionId);
    logger.auth('Session removed', { sessionId });
  }

  async removeAllUserSessions(userId: string): Promise<void> {
    const sessionsToRemove: string[] = [];
    
    for (const [sessionId, session] of this.sessions.entries()) {
      if (session.userId === userId) {
        sessionsToRemove.push(sessionId);
      }
    }
    
    for (const sessionId of sessionsToRemove) {
      this.sessions.delete(sessionId);
    }
    
    logger.auth('All user sessions removed', { userId, count: sessionsToRemove.length });
  }

  // Transaction operations
  async saveTransaction(transaction: TransactionSubmission): Promise<void> {
    this.transactions.set(transaction.txHash, transaction);
    logger.info('Transaction saved', { txHash: transaction.txHash });
  }

  async getTransaction(txHash: string): Promise<TransactionSubmission | null> {
    return this.transactions.get(txHash) || null;
  }

  async getTransactionsByUser(userId: string): Promise<TransactionSubmission[]> {
    const userTransactions: TransactionSubmission[] = [];
    
    for (const transaction of this.transactions.values()) {
      if (transaction.submittedBy === userId) {
        userTransactions.push(transaction);
      }
    }
    
    return userTransactions.sort((a, b) => b.submittedAt.getTime() - a.submittedAt.getTime());
  }

  // Cache operations
  async cacheSet(key: string, value: any, ttl?: number): Promise<void> {
    this.cache.set(key, value, ttl || 0);
  }

  async cacheGet<T>(key: string): Promise<T | null> {
    return this.cache.get<T>(key) || null;
  }

  async cacheDelete(key: string): Promise<void> {
    this.cache.del(key);
  }

  // Statistics
  async getStats(): Promise<{
    users: number;
    devices: number;
    activeSessions: number;
    transactions: number;
  }> {
    return {
      users: this.users.size,
      devices: this.devices.size,
      activeSessions: this.sessions.size,
      transactions: this.transactions.size,
    };
  }

  // Cleanup expired data
  private cleanup(): void {
    const now = new Date();
    
    // Clean up expired registration challenges
    for (const [challenge, data] of this.registrationChallenges.entries()) {
      if (data.expiresAt <= now) {
        this.registrationChallenges.delete(challenge);
      }
    }
    
    // Clean up expired authentication challenges
    for (const [challenge, data] of this.authenticationChallenges.entries()) {
      if (data.expiresAt <= now) {
        this.authenticationChallenges.delete(challenge);
      }
    }
    
    // Clean up expired sessions
    for (const [sessionId, session] of this.sessions.entries()) {
      if (session.expiresAt <= now) {
        this.sessions.delete(sessionId);
      }
    }
    
    logger.debug('Storage cleanup completed');
  }

  // Development/testing utilities
  async reset(): Promise<void> {
    this.cache.flushAll();
    this.users.clear();
    this.devices.clear();
    this.registrationChallenges.clear();
    this.authenticationChallenges.clear();
    this.sessions.clear();
    this.transactions.clear();
    this.usersByWallet.clear();
    this.usersByUsername.clear();
    this.devicesByUser.clear();
    
    logger.info('Storage reset completed');
  }

  async shutdown(): Promise<void> {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
    }
    this.cache.close();
    logger.info('Storage service shutdown completed');
  }
}

export const storageService = new StorageService();
