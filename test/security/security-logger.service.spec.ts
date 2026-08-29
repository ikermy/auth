import { Test, TestingModule } from '@nestjs/testing';
import { SecurityLoggerService } from '../../src/security/security-logger.service';
import { PrismaService } from '../../src/prisma.service';

describe('SecurityLoggerService', () => {
  let service: SecurityLoggerService;
  let mockLogger: any;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SecurityLoggerService,
        {
          provide: PrismaService,
          useValue: {
            securityEvent: {
              create: jest.fn(),
            },
          },
        },
      ],
    }).compile();

    service = module.get<SecurityLoggerService>(SecurityLoggerService);
    mockLogger = (service as any).logger;

    // Spy on the logger methods
    jest.spyOn(mockLogger, 'log').mockImplementation();
    jest.spyOn(mockLogger, 'warn').mockImplementation();
    jest.spyOn(mockLogger, 'error').mockImplementation();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('logSuspiciousActivity', () => {
    it('should log suspicious activity with correct format', () => {
      service.logSuspiciousActivity(
        '192.168.1.1',
        'POST',
        '/login',
        'Multiple failed attempts',
      );

      expect(mockLogger.warn).toHaveBeenCalledWith(
        expect.stringContaining('🚨'),
      );
      expect(mockLogger.warn).toHaveBeenCalledWith(
        expect.stringContaining('SUSPICIOUS_ACTIVITY'),
      );
      expect(mockLogger.warn).toHaveBeenCalledWith(
        expect.stringContaining('192.168.1.1'),
      );
    });
  });

  describe('logSuccess', () => {
    it('should log success with correct format', () => {
      service.logSuccess('192.168.1.1', 'POST', '/login');

      expect(mockLogger.log).toHaveBeenCalledWith(
        expect.stringContaining('✅'),
      );
      expect(mockLogger.log).toHaveBeenCalledWith(
        expect.stringContaining('SUCCESS'),
      );
    });
  });

  describe('logError', () => {
    it('should log error with correct format', () => {
      service.logError(
        '192.168.1.1',
        'POST',
        '/login',
        'Database connection failed',
      );

      expect(mockLogger.error).toHaveBeenCalledWith(
        expect.stringContaining('❌'),
      );
      expect(mockLogger.error).toHaveBeenCalledWith(
        expect.stringContaining('ERROR'),
      );
    });
  });

  describe('logRateLimitExceeded', () => {
    it('should log rate limit exceeded with correct format', () => {
      service.logRateLimitExceeded('192.168.1.1');

      expect(mockLogger.warn).toHaveBeenCalledWith(
        expect.stringContaining('⚠️'),
      );
      expect(mockLogger.warn).toHaveBeenCalledWith(
        expect.stringContaining('RATE_LIMIT_EXCEEDED'),
      );
    });
  });

  describe('logIpBlocked', () => {
    it('should log IP blocked with correct format', () => {
      service.logIpBlocked('192.168.1.1', 'Too many failed attempts');

      expect(mockLogger.warn).toHaveBeenCalledWith(
        expect.stringContaining('🚫'),
      );
      expect(mockLogger.warn).toHaveBeenCalledWith(
        expect.stringContaining('IP_BLOCKED'),
      );
    });
  });

  describe('logIpBlacklisted', () => {
    it('should log IP blacklisted with correct format', () => {
      service.logIpBlacklisted('192.168.1.1');

      expect(mockLogger.warn).toHaveBeenCalledWith(
        expect.stringContaining('🚫'),
      );
      expect(mockLogger.warn).toHaveBeenCalledWith(
        expect.stringContaining('IP_BLACKLISTED'),
      );
    });
  });

  describe('logIpWhitelisted', () => {
    it('should log IP whitelisted with correct format', () => {
      service.logIpWhitelisted('192.168.1.1');

      expect(mockLogger.log).toHaveBeenCalledWith(
        expect.stringContaining('✅'),
      );
      expect(mockLogger.log).toHaveBeenCalledWith(
        expect.stringContaining('IP_WHITELISTED'),
      );
    });
  });

  describe('logAuthAttempt', () => {
    it('should log successful auth attempt with correct format', () => {
      service.logAuthAttempt('192.168.1.1', 'user@example.com', true);

      expect(mockLogger.log).toHaveBeenCalledWith(
        expect.stringContaining('🔐'),
      );
      expect(mockLogger.log).toHaveBeenCalledWith(
        expect.stringContaining('SUCCESS'),
      );
    });

    it('should log failed auth attempt with correct format', () => {
      service.logAuthAttempt('192.168.1.1', 'user@example.com', false);

      expect(mockLogger.log).toHaveBeenCalledWith(
        expect.stringContaining('🔓'),
      );
      expect(mockLogger.log).toHaveBeenCalledWith(
        expect.stringContaining('FAILED'),
      );
    });
  });

  describe('logRegistration', () => {
    it('should log successful registration with correct format', () => {
      service.logRegistration('192.168.1.1', 'user@example.com', true);

      expect(mockLogger.log).toHaveBeenCalledWith(
        expect.stringContaining('📝'),
      );
      expect(mockLogger.log).toHaveBeenCalledWith(
        expect.stringContaining('SUCCESS'),
      );
    });

    it('should log failed registration with correct format', () => {
      service.logRegistration('192.168.1.1', 'user@example.com', false);

      expect(mockLogger.log).toHaveBeenCalledWith(
        expect.stringContaining('❌'),
      );
      expect(mockLogger.log).toHaveBeenCalledWith(
        expect.stringContaining('FAILED'),
      );
    });
  });

  describe('logTokenRefresh', () => {
    it('should log successful token refresh with correct format', () => {
      service.logTokenRefresh('192.168.1.1', true);

      expect(mockLogger.log).toHaveBeenCalledWith(
        expect.stringContaining('🔄'),
      );
      expect(mockLogger.log).toHaveBeenCalledWith(
        expect.stringContaining('SUCCESS'),
      );
    });

    it('should log failed token refresh with correct format', () => {
      service.logTokenRefresh('192.168.1.1', false);

      expect(mockLogger.log).toHaveBeenCalledWith(
        expect.stringContaining('❌'),
      );
      expect(mockLogger.log).toHaveBeenCalledWith(
        expect.stringContaining('FAILED'),
      );
    });
  });

  describe('logJwtEvent', () => {
    it('should log JWT event with correct format', () => {
      service.logJwtEvent('token_generated', 'Access token created');

      expect(mockLogger.log).toHaveBeenCalledWith(
        expect.stringContaining('🔑'),
      );
      expect(mockLogger.log).toHaveBeenCalledWith(
        expect.stringContaining('JWT'),
      );
    });
  });

  describe('logRedisEvent', () => {
    it('should log Redis event with correct format', () => {
      service.logRedisEvent('CONNECTED', 'Redis connection established');

      expect(mockLogger.log).toHaveBeenCalledWith(
        expect.stringContaining('🗄️'),
      );
      expect(mockLogger.log).toHaveBeenCalledWith(
        expect.stringContaining('REDIS'),
      );
    });
  });

  describe('logAnomaly', () => {
    it('should log anomaly with correct format', () => {
      service.logAnomaly('gRPC', 'user@example.com', {
        score: 0.8,
      });

      expect(mockLogger.log).toHaveBeenCalledWith(
        expect.stringContaining('🚨'),
      );
      expect(mockLogger.log).toHaveBeenCalledWith(
        expect.stringContaining('ANOMALY_DETECTED'),
      );
    });
  });
});
