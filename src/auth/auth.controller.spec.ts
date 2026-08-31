import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { TelegramAuthService } from './telegram-auth.service';
import { PrismaService } from '../prisma.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { SecurityLoggerService } from '../security/security-logger.service';
import { BruteForceService } from '../security/services/brute-force.service';
import { SecureAuthService } from '../security/services/secure-auth.service';
import { EnhancedJwtService } from '../security/services/enhanced-jwt.service';
import { TwoFactorAuthService } from '../security/services/two-factor-auth.service';
import { AnomalyDetectionService } from '../security/services/anomaly-detection.service';
import { EncryptionService } from '../security/services/encryption.service';
import { SessionService } from '../security/services/session.service';
import { UsernameService } from './services/username.service';
import { UserIdentityService } from './services/user-identity.service';

describe('AuthController', () => {
  let controller: AuthController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        AuthService,
        {
          provide: TelegramAuthService,
          useValue: {
            validateTelegramAuth: jest.fn(),
            authenticateOrCreateUser: jest.fn(),
            generateTokens: jest.fn(),
            linkTelegramToExistingAccount: jest.fn(),
            getTelegramUserInfo: jest.fn(),
          },
        },
        {
          provide: PrismaService,
          useValue: {
            user: {
              findUnique: jest.fn(),
              create: jest.fn(),
            },
          },
        },
        {
          provide: JwtService,
          useValue: {
            sign: jest.fn(),
          },
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn(),
          },
        },
        {
          provide: SecurityLoggerService,
          useValue: {
            logSuspiciousActivity: jest.fn(),
            logSuccess: jest.fn(),
            logError: jest.fn(),
            logAuthAttempt: jest.fn(),
            logAnomaly: jest.fn(),
          },
        },
        {
          provide: BruteForceService,
          useValue: {
            isBlocked: jest.fn(),
            recordFailedAttempt: jest.fn(),
          },
        },
        {
          provide: SecureAuthService,
          useValue: {
            authenticateUser: jest.fn(),
          },
        },
        {
          provide: EnhancedJwtService,
          useValue: {
            generateTokens: jest.fn(),
            verifyToken: jest.fn(),
          },
        },
        {
          provide: SessionService,
          useValue: {
            create: jest.fn(),
            findByRefreshJti: jest.fn(),
            deactivate: jest.fn(),
            deactivateAll: jest.fn(),
          },
        },
        {
          provide: TwoFactorAuthService,
          useValue: {
            generateSecret: jest.fn(),
            verifyToken: jest.fn(),
          },
        },
        {
          provide: AnomalyDetectionService,
          useValue: {
            analyzeUserBehavior: jest.fn(),
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
          provide: UsernameService,
          useValue: {
            generateUsername: jest.fn(),
            isValidUserUsername: jest.fn(),
            normalizeUserUsername: jest.fn(),
            generateAlternativeUsername: jest.fn(),
          },
        },
        {
          provide: UserIdentityService,
          useValue: {
            getUserIdentity: jest.fn(),
            changeUsername: jest.fn(),
            changeNickname: jest.fn(),
            canChangeUsername: jest.fn(),
            suggestUsernameAlternatives: jest.fn(),
            generateUsernameAlternatives: jest.fn(),
          },
        },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
