import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from '../../src/auth/auth.controller';
import { AuthService } from '../../src/auth/auth.service';
import { SecureAuthService } from '../../src/security/services/secure-auth.service';
import { EnhancedJwtService } from '../../src/security/services/enhanced-jwt.service';
import { BruteForceService } from '../../src/security/services/brute-force.service';
import { TwoFactorAuthService } from '../../src/security/services/two-factor-auth.service';
import { AnomalyDetectionService } from '../../src/security/services/anomaly-detection.service';
import { EncryptionService } from '../../src/security/services/encryption.service';
import { PrismaService } from '../../src/prisma.service';
import { SecurityLoggerService } from '../../src/security/security-logger.service';

describe('AuthController', () => {
  let controller: AuthController;
  let authService: AuthService;
  let secureAuthService: SecureAuthService;
  let enhancedJwtService: EnhancedJwtService;
  let bruteForceService: BruteForceService;
  let twoFactorAuthService: TwoFactorAuthService;
  let anomalyDetectionService: AnomalyDetectionService;
  let encryptionService: EncryptionService;
  let prismaService: PrismaService;
  let securityLogger: SecurityLoggerService;

  const mockUser = {
    id: '1',
    email: 'test@example.com',
    password: '$2b$10$hashedpassword',
    isActive: true,
  };

  const mockTokens = {
    accessToken: 'mock.access.token',
    refreshToken: 'mock.refresh.token',
    accessTokenId: 'access-123',
    refreshTokenId: 'refresh-123',
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        {
          provide: AuthService,
          useValue: {
            register: jest.fn(),
            login: jest.fn(),
            refreshToken: jest.fn(),
            logout: jest.fn(),
          },
        },
        {
          provide: SecureAuthService,
          useValue: {
            authenticateUser: jest.fn(),
            validatePasswordStrength: jest.fn(),
          },
        },
        {
          provide: EnhancedJwtService,
          useValue: {
            generateTokens: jest.fn(),
            verifyToken: jest.fn(),
            revokeToken: jest.fn(),
          },
        },
        {
          provide: BruteForceService,
          useValue: {
            isBlocked: jest.fn(),
            recordFailedAttempt: jest.fn(),
            clearFailedAttempts: jest.fn(),
          },
        },
        {
          provide: TwoFactorAuthService,
          useValue: {
            is2FAEnabled: jest.fn(),
            verify2FA: jest.fn(),
            enable2FA: jest.fn(),
            disable2FA: jest.fn(),
          },
        },
        {
          provide: AnomalyDetectionService,
          useValue: {
            analyzeUserBehavior: jest.fn(),
            getAnomalyStats: jest.fn(),
          },
        },
        {
          provide: EncryptionService,
          useValue: {
            encrypt: jest.fn(),
            decrypt: jest.fn(),
          },
        },
        {
          provide: PrismaService,
          useValue: {
            user: {
              findUnique: jest.fn(),
            },
          },
        },
        {
          provide: SecurityLoggerService,
          useValue: {
            logSecurityEvent: jest.fn(),
            logSecurityError: jest.fn(),
            logGrpc: jest.fn(),
            logAnomaly: jest.fn(),
          },
        },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
    authService = module.get<AuthService>(AuthService);
    secureAuthService = module.get<SecureAuthService>(SecureAuthService);
    enhancedJwtService = module.get<EnhancedJwtService>(EnhancedJwtService);
    bruteForceService = module.get<BruteForceService>(BruteForceService);
    twoFactorAuthService =
      module.get<TwoFactorAuthService>(TwoFactorAuthService);
    anomalyDetectionService = module.get<AnomalyDetectionService>(
      AnomalyDetectionService,
    );
    encryptionService = module.get<EncryptionService>(EncryptionService);
    prismaService = module.get<PrismaService>(PrismaService);
    securityLogger = module.get<SecurityLoggerService>(SecurityLoggerService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('register', () => {
    it('should register new user successfully', async () => {
      const registerRequest = {
        email: 'newuser@example.com',
        password: 'StrongPass123!',
      };

      (secureAuthService.validatePasswordStrength as jest.Mock).mockReturnValue(
        {
          valid: true,
          errors: [],
        },
      );
      (authService.register as jest.Mock).mockResolvedValue({
        success: true,
        user: mockUser,
      });

      const result = await controller.register(registerRequest);

      expect(result.success).toBe(true);
      expect(secureAuthService.validatePasswordStrength).toHaveBeenCalledWith(
        'StrongPass123!',
      );
      expect(authService.register).toHaveBeenCalledWith(registerRequest);
    });

    it('should fail registration with weak password', async () => {
      const registerRequest = {
        email: 'newuser@example.com',
        password: 'weak',
      };

      (secureAuthService.validatePasswordStrength as jest.Mock).mockReturnValue(
        {
          valid: false,
          errors: ['Password too weak'],
        },
      );

      const result = await controller.register(registerRequest);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Password validation failed');
    });
  });

  describe('login', () => {
    it('should login user successfully', async () => {
      const loginRequest = {
        email: 'test@example.com',
        password: 'password123',
      };

      (bruteForceService.isBlocked as jest.Mock).mockResolvedValue(false);
      (secureAuthService.authenticateUser as jest.Mock).mockResolvedValue({
        success: true,
        user: mockUser,
      });
      (enhancedJwtService.generateTokens as jest.Mock).mockResolvedValue(
        mockTokens,
      );
      (twoFactorAuthService.is2FAEnabled as jest.Mock).mockResolvedValue(false);
      (
        anomalyDetectionService.analyzeUserBehavior as jest.Mock
      ).mockResolvedValue({
        score: 0.2,
        factors: [],
        threshold: 0.7,
      });
      (encryptionService.encrypt as jest.Mock).mockReturnValue(
        'encrypted-token',
      );

      const result = await controller.login(loginRequest);

      expect(result.success).toBe(true);
      expect(result.accessToken).toBe('encrypted-token');
      expect(bruteForceService.clearFailedAttempts).toHaveBeenCalledWith(
        'test@example.com',
      );
    });

    it('should fail login if user is blocked', async () => {
      const loginRequest = {
        email: 'test@example.com',
        password: 'password123',
      };

      (bruteForceService.isBlocked as jest.Mock).mockResolvedValue(true);

      const result = await controller.login(loginRequest);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Account temporarily blocked');
    });

    it('should fail login with invalid credentials', async () => {
      const loginRequest = {
        email: 'test@example.com',
        password: 'wrongpassword',
      };

      (bruteForceService.isBlocked as jest.Mock).mockResolvedValue(false);
      (secureAuthService.authenticateUser as jest.Mock).mockResolvedValue({
        success: false,
        user: undefined,
      });

      const result = await controller.login(loginRequest);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid credentials');
      expect(bruteForceService.recordFailedAttempt).toHaveBeenCalledWith(
        'test@example.com',
      );
    });

    it('should require 2FA if enabled', async () => {
      const loginRequest = {
        email: 'test@example.com',
        password: 'password123',
      };

      (bruteForceService.isBlocked as jest.Mock).mockResolvedValue(false);
      (secureAuthService.authenticateUser as jest.Mock).mockResolvedValue({
        success: true,
        user: mockUser,
      });
      (twoFactorAuthService.is2FAEnabled as jest.Mock).mockResolvedValue(true);

      const result = await controller.login(loginRequest);

      expect(result.success).toBe(false);
      expect(result.error).toBe('2FA_REQUIRED');
    });

    it('should detect anomaly and log it', async () => {
      const loginRequest = {
        email: 'test@example.com',
        password: 'password123',
      };

      (bruteForceService.isBlocked as jest.Mock).mockResolvedValue(false);
      (secureAuthService.authenticateUser as jest.Mock).mockResolvedValue({
        success: true,
        user: mockUser,
      });
      (twoFactorAuthService.is2FAEnabled as jest.Mock).mockResolvedValue(false);
      (
        anomalyDetectionService.analyzeUserBehavior as jest.Mock
      ).mockResolvedValue({
        score: 0.8,
        factors: ['unusual_time', 'new_ip'],
        threshold: 0.7,
      });

      const result = await controller.login(loginRequest);

      expect(securityLogger.logAnomaly).toHaveBeenCalledWith(
        'suspicious_login',
        expect.stringContaining('Score: 0.8'),
      );
    });
  });

  describe('enable2FA', () => {
    it('should enable 2FA successfully', async () => {
      const request = { userId: '1' };

      (twoFactorAuthService.enable2FA as jest.Mock).mockResolvedValue({
        success: true,
        qrCode: 'data:image/png;base64,test',
        backupCodes: ['code1', 'code2'],
      });

      const result = await controller.enable2FA(request);

      expect(result.success).toBe(true);
      expect(result.qrCode).toBeDefined();
      expect(result.backupCodes).toHaveLength(2);
    });

    it('should fail to enable 2FA', async () => {
      const request = { userId: '1' };

      (twoFactorAuthService.enable2FA as jest.Mock).mockResolvedValue({
        success: false,
        error: 'User not found',
      });

      const result = await controller.enable2FA(request);

      expect(result.success).toBe(false);
      expect(result.error).toBe('User not found');
    });
  });

  describe('verify2FA', () => {
    it('should verify 2FA successfully', async () => {
      const request = {
        userId: '1',
        token: '123456',
      };

      (twoFactorAuthService.verify2FA as jest.Mock).mockResolvedValue({
        success: true,
        backupCodeUsed: false,
      });

      const result = await controller.verify2FA(request);

      expect(result.success).toBe(true);
    });

    it('should fail 2FA verification', async () => {
      const request = {
        userId: '1',
        token: 'invalid',
      };

      (twoFactorAuthService.verify2FA as jest.Mock).mockResolvedValue({
        success: false,
        error: 'Invalid 2FA token',
      });

      const result = await controller.verify2FA(request);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid 2FA token');
    });
  });

  describe('getAnomalyStats', () => {
    it('should return anomaly statistics', async () => {
      const request = { userId: '1' };

      (anomalyDetectionService.getAnomalyStats as jest.Mock).mockResolvedValue({
        totalEvents: 10,
        anomalyEvents: 2,
        averageScore: 0.3,
        lastAnomaly: new Date(),
      });

      const result = await controller.getAnomalyStats(request);

      expect(result.totalEvents).toBe(10);
      expect(result.anomalyEvents).toBe(2);
      expect(result.averageScore).toBe(0.3);
    });
  });
});
