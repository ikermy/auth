import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { EnhancedJwtService } from '../../src/security/services/enhanced-jwt.service';
import { SessionService } from '../../src/security/services/session.service';
import { SecurityLoggerService } from '../../src/security/security-logger.service';

// Mock Redis
jest.mock('redis', () => ({
  createClient: jest.fn(() => ({
    connect: jest.fn(),
    get: jest.fn(),
    set: jest.fn(),
    del: jest.fn(),
    keys: jest.fn(),
  })),
}));

describe('EnhancedJwtService', () => {
  let service: EnhancedJwtService;
  let jwtService: JwtService;
  let configService: ConfigService;
  let securityLogger: SecurityLoggerService;

  const mockTokens = {
    accessToken: 'mock.access.token',
    refreshToken: 'mock.refresh.token',
    accessTokenId: 'access-123',
    refreshTokenId: 'refresh-123',
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        EnhancedJwtService,
        {
          provide: JwtService,
          useValue: {
            signAsync: jest.fn().mockResolvedValue('mock.token'),
            verifyAsync: jest.fn().mockResolvedValue({
              sub: '1',
              email: 'test@example.com',
              jti: 'token-123',
              type: 'access',
            }),
          },
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string, defaultValue?: any) => {
              const config: Record<string, any> = {
                REDIS_HOST: 'localhost',
                REDIS_PORT: 6379,
                REDIS_PASSWORD: '',
                REDIS_USERNAME: '',
              };
              return config[key] || defaultValue;
            }),
          },
        },
        {
          provide: SecurityLoggerService,
          useValue: {
            logJwtEvent: jest.fn(),
            logRedisEvent: jest.fn(),
            logSecurityError: jest.fn(),
          },
        },
        {
          provide: SessionService,
          useValue: {
            create: jest.fn().mockResolvedValue({ id: 'session-1' }),
            findByRefreshJti: jest.fn(),
            deactivate: jest.fn(),
            deactivateAll: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<EnhancedJwtService>(EnhancedJwtService);
    jwtService = module.get<JwtService>(JwtService);
    configService = module.get<ConfigService>(ConfigService);
    securityLogger = module.get<SecurityLoggerService>(SecurityLoggerService);

    // Mock Redis methods
    (service as any).redisClient = {
      connect: jest.fn(),
      get: jest.fn().mockResolvedValue(null), // Default to not revoked
      set: jest.fn(),
      setEx: jest.fn(),
      del: jest.fn(),
      keys: jest.fn().mockResolvedValue([]),
    };
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('generateTokens', () => {
    it('should generate access and refresh tokens', async () => {
      const result = await service.generateTokens('1', 'test@example.com');

      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
      expect(result.accessTokenId).toBeDefined();
      expect(result.refreshTokenId).toBeDefined();
    });

    it('should call JWT service with correct payload', async () => {
      await service.generateTokens('1', 'test@example.com');

      expect(jwtService.signAsync).toHaveBeenCalledTimes(2);
    });

    it('should log token generation', async () => {
      await service.generateTokens('1', 'test@example.com');

      expect(securityLogger.logJwtEvent).toHaveBeenCalledWith(
        'tokens_generated',
        expect.stringContaining('User: 1'),
      );
    });
  });

  describe('verifyToken', () => {
    it('should verify valid token', async () => {
      const result = await service.verifyToken('valid.token');

      expect(result).toBeDefined();
      expect(result.sub).toBe('1');
      expect(result.email).toBe('test@example.com');
    });

    it('should throw error for invalid token', async () => {
      (jwtService.verifyAsync as jest.Mock).mockRejectedValue(
        new Error('Invalid token'),
      );

      await expect(service.verifyToken('invalid.token')).rejects.toThrow(
        'Invalid token',
      );
    });

    it('should log verification failure', async () => {
      (jwtService.verifyAsync as jest.Mock).mockRejectedValue(
        new Error('Invalid token'),
      );

      try {
        await service.verifyToken('invalid.token');
      } catch (error) {
        // Expected to throw
      }

      expect(securityLogger.logJwtEvent).toHaveBeenCalledWith(
        'token_verification_failed',
        expect.stringContaining('Invalid token'),
      );
    });
  });

  describe('revokeToken', () => {
    it('should revoke token by JTI', async () => {
      await service.revokeToken('token-123');

      expect(securityLogger.logJwtEvent).toHaveBeenCalledWith(
        'token_revoked',
        'JTI: token-123',
      );
    });
  });

  describe('revokeAllUserTokens', () => {
    it('should revoke all tokens for user', async () => {
      (service as any).redisClient.keys.mockResolvedValue([
        'token1',
        'token2',
        'token3',
      ]);

      await service.revokeAllUserTokens('1');

      expect(securityLogger.logJwtEvent).toHaveBeenCalledWith(
        'all_user_tokens_revoked',
        'User: 1',
      );
    });
  });

  describe('getUserActiveTokens', () => {
    it('should return active tokens for user', async () => {
      const result = await service.getUserActiveTokens('1');

      expect(Array.isArray(result)).toBe(true);
    });
  });

  describe('isTokenRevoked', () => {
    it('should return false for non-revoked token', async () => {
      const result = await (service as any).isTokenRevoked('token-123');

      expect(result).toBe(false);
    });

    it('should return true for revoked token', async () => {
      (service as any).redisClient.get.mockResolvedValueOnce('1');
      const result = await (service as any).isTokenRevoked('token-123');

      expect(result).toBe(true);
    });
  });
});
