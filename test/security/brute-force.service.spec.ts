import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { BruteForceService } from '../../src/security/services/brute-force.service';
import { SecurityLoggerService } from '../../src/security/security-logger.service';

// Mock Redis
jest.mock('redis', () => ({
  createClient: jest.fn(() => ({
    connect: jest.fn(),
    get: jest.fn(),
    incr: jest.fn(),
    expire: jest.fn(),
    del: jest.fn(),
    ttl: jest.fn(),
  })),
}));

describe('BruteForceService', () => {
  let service: BruteForceService;
  let configService: ConfigService;
  let securityLogger: SecurityLoggerService;

  beforeEach(async () => {
    const mockRedisClient = {
      connect: jest.fn(),
      get: jest.fn(),
      incr: jest.fn(),
      expire: jest.fn(),
      del: jest.fn(),
      ttl: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        BruteForceService,
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
            logSecurityError: jest.fn(),
            logRedisEvent: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<BruteForceService>(BruteForceService);
    configService = module.get<ConfigService>(ConfigService);
    securityLogger = module.get<SecurityLoggerService>(SecurityLoggerService);

    // Mock Redis methods
    (service as any).redisClient = mockRedisClient;
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('isBlocked', () => {
    it('should return false for new key', async () => {
      (service as any).redisClient.get.mockResolvedValue(null);
      const result = await service.isBlocked('test@example.com');
      expect(result).toBe(false);
    });

    it('should return true after 5 failed attempts', async () => {
      const email = 'test@example.com';

      (service as any).redisClient.get.mockResolvedValue('5');
      const result = await service.isBlocked(email);
      expect(result).toBe(true);
    });
  });

  describe('recordFailedAttempt', () => {
    it('should increment failed attempts counter', async () => {
      const email = 'test@example.com';

      (service as any).redisClient.incr.mockResolvedValue(2);
      (service as any).redisClient.get.mockResolvedValue('2');

      await service.recordFailedAttempt(email);
      await service.recordFailedAttempt(email);

      const isBlocked = await service.isBlocked(email);
      expect(isBlocked).toBe(false); // Still under limit
    });

    it('should log security error on 5th attempt', async () => {
      const email = 'test@example.com';

      (service as any).redisClient.incr.mockResolvedValue(5);

      await service.recordFailedAttempt(email);

      expect(securityLogger.logSecurityError).toHaveBeenCalledWith(
        'BRUTE_FORCE_DETECTED',
        `Key: ${email}`,
      );
    });
  });

  describe('clearFailedAttempts', () => {
    it('should clear failed attempts for key', async () => {
      const email = 'test@example.com';

      (service as any).redisClient.del.mockResolvedValue(1);
      (service as any).redisClient.get.mockResolvedValue(null);

      await service.clearFailedAttempts(email);

      const isBlocked = await service.isBlocked(email);
      expect(isBlocked).toBe(false);
    });
  });

  describe('getBlockTimeRemaining', () => {
    it('should return remaining time for blocked key', async () => {
      const email = 'test@example.com';

      for (let i = 0; i < 5; i++) {
        await service.recordFailedAttempt(email);
      }

      (service as any).redisClient.ttl.mockResolvedValue(300); // 5 minutes
      const remainingTime = await service.getBlockTimeRemaining(email);
      expect(remainingTime).toBeGreaterThan(0);
    });
  });
});
