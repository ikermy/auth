import { config } from 'dotenv';

// Load test environment variables
config({ path: '.env.test' });

// Mock Redis for tests
jest.mock('redis', () => ({
  createClient: jest.fn(() => ({
    connect: jest.fn().mockResolvedValue(undefined),
    disconnect: jest.fn().mockResolvedValue(undefined),
    get: jest.fn().mockResolvedValue(null),
    set: jest.fn().mockResolvedValue('OK'),
    setEx: jest.fn().mockResolvedValue('OK'),
    del: jest.fn().mockResolvedValue(1),
    exists: jest.fn().mockResolvedValue(0),
    ttl: jest.fn().mockResolvedValue(-1),
    keys: jest.fn().mockResolvedValue([]),
    on: jest.fn(),
  })),
}));

// Mock bcrypt for consistent testing
jest.mock('bcrypt', () => ({
  hash: jest.fn().mockResolvedValue('$2b$10$hashedpassword'),
  compare: jest.fn().mockResolvedValue(true),
  genSalt: jest.fn().mockResolvedValue('$2b$10$salt'),
}));

// Mock speakeasy for 2FA testing
jest.mock('speakeasy', () => ({
  generateSecret: jest.fn().mockReturnValue({
    base32: 'test-secret',
    otpauth_url: 'otpauth://totp/test',
  }),
  totp: {
    verify: jest.fn().mockReturnValue(true),
  },
}));

// Mock qrcode for 2FA testing
jest.mock('qrcode', () => ({
  toDataURL: jest.fn().mockResolvedValue('data:image/png;base64,test'),
}));

// Mock crypto for encryption testing
jest.mock('crypto', () => ({
  randomBytes: jest.fn().mockReturnValue(Buffer.from('test-random-bytes')),
  createCipher: jest.fn().mockReturnValue({
    update: jest.fn().mockReturnValue(Buffer.from('encrypted')),
    final: jest.fn().mockReturnValue(Buffer.from('final')),
  }),
  createDecipher: jest.fn().mockReturnValue({
    update: jest.fn().mockReturnValue(Buffer.from('decrypted')),
    final: jest.fn().mockReturnValue(Buffer.from('final')),
  }),
  createHash: jest.fn().mockReturnValue({
    update: jest.fn().mockReturnThis(),
    digest: jest.fn().mockReturnValue('hashed-value'),
  }),
  createHmac: jest.fn().mockReturnValue({
    update: jest.fn().mockReturnThis(),
    digest: jest.fn().mockReturnValue('signed-value'),
  }),
}));

// Global test timeout
jest.setTimeout(30000);

// Suppress console logs during tests unless explicitly needed
const originalConsoleLog = console.log;
const originalConsoleError = console.error;
const originalConsoleWarn = console.warn;

beforeAll(() => {
  console.log = jest.fn();
  console.error = jest.fn();
  console.warn = jest.fn();
});

afterAll(() => {
  console.log = originalConsoleLog;
  console.error = originalConsoleError;
  console.warn = originalConsoleWarn;
});

// Clean up after each test
afterEach(() => {
  jest.clearAllMocks();
});

// Global test utilities
global.testUtils = {
  createMockUser: (overrides = {}) => ({
    id: '1',
    email: 'test@example.com',
    password: '$2b$10$hashedpassword',
    isActive: true,
    createdAt: new Date(),
    updatedAt: new Date(),
    twoFactorSecret: null,
    twoFactorEnabled: false,
    backupCodes: [],
    ...overrides,
  }),

  createMockTokens: () => ({
    accessToken: 'mock.access.token',
    refreshToken: 'mock.refresh.token',
    accessTokenId: 'access-123',
    refreshTokenId: 'refresh-123',
  }),

  createMockLoginAttempt: (overrides = {}) => ({
    id: '1',
    userId: '1',
    email: 'test@example.com',
    ipAddress: '192.168.1.1',
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    success: true,
    failureReason: null,
    timestamp: new Date(),
    ...overrides,
  }),

  wait: (ms: number) => new Promise((resolve) => setTimeout(resolve, ms)),

  generateRandomEmail: () => `test-${Date.now()}@example.com`,

  generateStrongPassword: () => 'StrongPass123!',

  generateWeakPassword: () => 'weak',
};
