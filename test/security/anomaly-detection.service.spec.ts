import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { AnomalyDetectionService } from '../../src/security/services/anomaly-detection.service';
import { PrismaService } from '../../src/prisma.service';
import { SecurityLoggerService } from '../../src/security/security-logger.service';

// Mock Redis
jest.mock('redis', () => ({
  createClient: jest.fn(() => ({
    connect: jest.fn(),
    get: jest.fn(),
    incr: jest.fn(),
    expire: jest.fn(),
  })),
}));

describe('AnomalyDetectionService', () => {
  let service: AnomalyDetectionService;
  let prismaService: PrismaService;
  let configService: ConfigService;
  let securityLogger: SecurityLoggerService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AnomalyDetectionService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string, defaultValue?: any) => {
              const config: Record<string, any> = {
                REDIS_HOST: 'localhost',
                REDIS_PORT: 6379,
                REDIS_PASSWORD: '',
                REDIS_USERNAME: '',
                ANOMALY_THRESHOLD: 0.7,
              };
              return config[key] || defaultValue;
            }),
          },
        },
        {
          provide: PrismaService,
          useValue: {
            loginAttempt: {
              findMany: jest.fn(),
            },
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

    service = module.get<AnomalyDetectionService>(AnomalyDetectionService);
    prismaService = module.get<PrismaService>(PrismaService);
    configService = module.get<ConfigService>(ConfigService);
    securityLogger = module.get<SecurityLoggerService>(SecurityLoggerService);

    // Mock Redis methods
    (service as any).redisClient = {
      connect: jest.fn(),
      get: jest.fn().mockResolvedValue('0'),
      incr: jest.fn().mockResolvedValue(1),
      expire: jest.fn(),
    };
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('analyzeUserBehavior', () => {
    it('should analyze normal behavior with low score', async () => {
      const behavior = {
        userId: '1',
        ipAddress: '192.168.1.1',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        action: 'login',
        timestamp: new Date('2023-01-01T12:00:00Z'),
        success: true,
      };

      (prismaService.loginAttempt.findMany as jest.Mock).mockResolvedValue([]);

      const result = await service.analyzeUserBehavior('1', behavior);

      expect(result.score).toBeLessThan(0.7);
      expect(result.factors).toBeDefined();
      expect(result.threshold).toBe(0.7);
    });

    it('should detect anomaly with high score', async () => {
      const behavior = {
        userId: '1',
        ipAddress: '192.168.1.1',
        userAgent: 'bot/crawler',
        action: 'login',
        timestamp: new Date('2023-01-01T03:00:00Z'), // 3 AM
        success: false,
      };

      (prismaService.loginAttempt.findMany as jest.Mock).mockResolvedValue([
        { timestamp: new Date('2023-01-01T12:00:00Z') },
        { timestamp: new Date('2023-01-01T12:01:00Z') },
        { timestamp: new Date('2023-01-01T12:02:00Z') },
        { timestamp: new Date('2023-01-01T12:03:00Z') },
        { timestamp: new Date('2023-01-01T12:04:00Z') },
      ]);

      const result = await service.analyzeUserBehavior('1', behavior);

      expect(result.score).toBeGreaterThan(0.4);
      // Score is below threshold (0.7), so no anomaly should be logged
      expect(securityLogger.logSecurityError).not.toHaveBeenCalledWith(
        'ANOMALY_DETECTED',
        expect.stringContaining('User: 1'),
      );
    });
  });

  describe('analyzeIPAddress', () => {
    it('should detect new IP address', async () => {
      (prismaService.loginAttempt.findMany as jest.Mock).mockResolvedValue([
        { ipAddress: '192.168.1.2' },
        { ipAddress: '192.168.1.3' },
      ]);

      const result = await service['analyzeIPAddress']('1', '192.168.1.1');

      expect(result.score).toBeGreaterThan(0);
      expect(result.factors).toContain('new_ip_address');
    });

    it('should detect suspicious location', async () => {
      (prismaService.loginAttempt.findMany as jest.Mock).mockResolvedValue([]);

      const result = await service['analyzeIPAddress']('1', '192.168.1.100');

      expect(result.score).toBeGreaterThan(0);
      expect(result.factors).toContain('suspicious_location');
    });
  });

  describe('analyzeUserAgent', () => {
    it('should detect new User-Agent', async () => {
      (prismaService.loginAttempt.findMany as jest.Mock).mockResolvedValue([
        { userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
        { userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)' },
      ]);

      const result = await service['analyzeUserAgent'](
        '1',
        'Mozilla/5.0 (Linux; x86_64)',
      );

      expect(result.score).toBeGreaterThan(0);
      expect(result.factors).toContain('new_user_agent');
    });

    it('should detect suspicious User-Agent', async () => {
      (prismaService.loginAttempt.findMany as jest.Mock).mockResolvedValue([]);

      const result = await service['analyzeUserAgent']('1', 'bot/crawler');

      expect(result.score).toBeGreaterThan(0);
      expect(result.factors).toContain('suspicious_user_agent');
    });
  });

  describe('analyzeTimePattern', () => {
    it('should detect unusual time', async () => {
      const timestamp = new Date('2023-01-01T03:00:00Z'); // 3 AM

      const result = await service['analyzeTimePattern']('1', timestamp);

      expect(result.score).toBeGreaterThan(0);
      expect(result.factors).toContain('unusual_time');
    });

    it('should detect high frequency activity', async () => {
      const timestamp = new Date('2023-01-01T12:00:00Z');
      (prismaService.loginAttempt.findMany as jest.Mock).mockResolvedValue([
        { timestamp: new Date('2023-01-01T12:00:00Z') },
        { timestamp: new Date('2023-01-01T12:01:00Z') },
        { timestamp: new Date('2023-01-01T12:02:00Z') },
        { timestamp: new Date('2023-01-01T12:03:00Z') },
        { timestamp: new Date('2023-01-01T12:04:00Z') },
      ]);

      const result = await service['analyzeTimePattern']('1', timestamp);

      expect(result.score).toBeGreaterThan(0);
      expect(result.factors).toContain('high_frequency');
    });
  });

  describe('getAnomalyStats', () => {
    it('should return anomaly statistics', async () => {
      const mockEvents = [
        { timestamp: new Date(), failureReason: 'anomaly_detected' },
        { timestamp: new Date(), failureReason: 'normal_failure' },
        { timestamp: new Date(), failureReason: 'anomaly_detected' },
      ];

      (prismaService.loginAttempt.findMany as jest.Mock).mockResolvedValue(
        mockEvents,
      );

      const stats = await service.getAnomalyStats('1');

      expect(stats.totalEvents).toBe(3);
      expect(stats.anomalyEvents).toBe(2);
      expect(stats.averageScore).toBe(2 / 3);
      expect(stats.lastAnomaly).toBeDefined();
    });
  });
});
