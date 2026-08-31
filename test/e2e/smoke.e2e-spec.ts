import { Test, TestingModule } from '@nestjs/testing';
import { INestMicroservice } from '@nestjs/common';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { ConfigService } from '@nestjs/config';
import { join } from 'path';
import { AppModule } from '../../src/app.module';
import { PrismaService } from '../../src/prisma.service';
import { AuthController } from '../../src/auth/auth.controller';
import { ServiceAccessController } from '../../src/auth/service-access.controller';
import { EnhancedJwtService } from '../../src/security/services/enhanced-jwt.service';
import { BruteForceService } from '../../src/security/services/brute-force.service';
import { AnomalyDetectionService } from '../../src/security/services/anomaly-detection.service';
import { KafkaProducerService } from '../../src/security/services/kafka-producer.service';
import { TlsSecurityService } from '../../src/security/services/tls-security.service';
import { UserMonitoringService } from '../../src/cron/user-monitoring.service';

// Mock Prisma: e2e-смоук не требует реальной БД/Redis/Kafka.
function createMockPrisma() {
  const user = {
    findUnique: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    findMany: jest.fn(),
    count: jest.fn(),
  };
  const session = {
    create: jest.fn(),
    findUnique: jest.fn(),
    update: jest.fn(),
    updateMany: jest.fn(),
  };
  const loginAttempt = { findMany: jest.fn().mockResolvedValue([]), count: jest.fn().mockResolvedValue(0) };
  const securityEvent = { create: jest.fn(), findMany: jest.fn(), count: jest.fn() };
  const telegramIdentityAudit = { create: jest.fn(), findMany: jest.fn(), count: jest.fn() };
  const recoveryRequest = { create: jest.fn(), findUnique: jest.fn(), update: jest.fn() };
  const usernameReservation = { create: jest.fn(), findUnique: jest.fn(), update: jest.fn() };

  return {
    user,
    session,
    loginAttempt,
    securityEvent,
    telegramIdentityAudit,
    recoveryRequest,
    usernameReservation,
    $transaction: jest.fn(async (cb: any) => cb({ user, session, loginAttempt, securityEvent })),
  } as any;
}

describe('gRPC E2E smoke (сборка реального AppModule)', () => {
  let app: INestMicroservice;
  const mockPrisma = createMockPrisma();

  beforeAll(async () => {
    process.env.JWT_SUPER_SECRET_WORD = 'test-secret';
    process.env.ENCRYPTION_KEY = '0123456789abcdef0123456789abcdef';
    process.env.REDIS_HOST = 'localhost';
    process.env.REDIS_PORT = '6379';

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(PrismaService)
      .useValue(mockPrisma)
      .overrideProvider(ConfigService)
      .useValue({
        get: jest.fn((key: string, def?: any) => {
          const cfg: Record<string, any> = {
            JWT_SUPER_SECRET_WORD: 'test-secret',
            ENCRYPTION_KEY: '0123456789abcdef0123456789abcdef',
            REDIS_HOST: 'localhost',
            REDIS_PORT: 6379,
            KAFKA_BROKERS: '',
            ANOMALY_THRESHOLD: 0.7,
            TOTP_ISSUER: 'Test',
            USERNAME_GRACE_PERIOD_DAYS: 30,
            RECOVERY_GRANT_TTL_SECONDS: 86400,
          };
          return cfg[key] ?? def;
        }),
        getOrThrow: jest.fn((key: string) => {
          const cfg: Record<string, any> = {
            JWT_SUPER_SECRET_WORD: 'test-secret',
            JWT_EXPIRES_IN: '15m',
            JWT_REFRESH_IN: '7d',
          };
          return cfg[key];
        }),
      })
      .overrideProvider(EnhancedJwtService)
      .useValue({
        generateTokens: jest.fn().mockResolvedValue({
          accessToken: 'at',
          refreshToken: 'rt',
          accessTokenId: 'a1',
          refreshTokenId: 'r1',
          sessionId: 's1',
        }),
        verifyToken: jest.fn().mockResolvedValue({ sub: 'u1', email: 'x@x.com' }),
      })
      .overrideProvider(BruteForceService)
      .useValue({
        isBlocked: jest.fn().mockResolvedValue(false),
        recordFailedAttempt: jest.fn(),
        clearFailedAttempts: jest.fn(),
      })
      .overrideProvider(AnomalyDetectionService)
      .useValue({
        analyzeUserBehavior: jest.fn().mockResolvedValue({ score: 0, factors: [], threshold: 0.7 }),
        getAnomalyStats: jest.fn().mockResolvedValue({
          totalEvents: 0,
          anomalyEvents: 0,
          averageScore: 0,
          lastAnomaly: null,
        }),
      })
      .overrideProvider(KafkaProducerService)
      .useValue({ publish: jest.fn() })
      .overrideProvider(TlsSecurityService)
      .useValue({ isTlsEnabled: jest.fn().mockReturnValue(false), getTlsPort: jest.fn().mockReturnValue(0) })
      .overrideProvider(UserMonitoringService)
      .useValue({})
      .compile();

    app = moduleFixture.createNestMicroservice<MicroserviceOptions>({
      transport: Transport.GRPC,
      options: {
        package: 'auth',
        protoPath: join(__dirname, '../../src/auth/auth.proto'),
        url: 'localhost:0', // не открываем реальный сокет в CI
      },
    });

    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('AppModule компилируется и создаёт gRPC-микросервис', () => {
    expect(app).toBeDefined();
  });

  it('AuthController и ServiceAccessController зарегистрированы (gRPC-методы proto-сервиса)', () => {
    const authController = app.get(AuthController);
    const serviceAccess = app.get(ServiceAccessController);
    expect(authController).toBeDefined();
    expect(serviceAccess).toBeDefined();
  });

  it('register: обработчик возвращает token pair через мок EnhancedJwtService', async () => {
    mockPrisma.user.findUnique.mockResolvedValue(null);
    mockPrisma.user.create.mockResolvedValue({
      id: 'u1',
      email: 'smoke@test.com',
      password: 'hashed',
      origin: 'email',
    });
    mockPrisma.session.create.mockResolvedValue({ id: 's1' });

    const controller = app.get(AuthController);
    const result = await controller.register({
      email: 'smoke@test.com',
      password: 'StrongPass123!',
    } as any);

    expect(result.accessToken).toBe('at');
    expect(result.refreshToken).toBe('rt');
  });

  it('register: слабый пароль отклоняется (валидация DTO)', async () => {
    const controller = app.get(AuthController);
    await expect(
      controller.register({ email: 'weak@test.com', password: 'weak' } as any),
    ).rejects.toBeDefined();
  });
});
