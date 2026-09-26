import { Test, TestingModule } from '@nestjs/testing';
import { RpcException } from '@nestjs/microservices';
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
import { TelegramUsernameHistoryService } from './services/telegram-username-history.service';
import { EmailVerificationService } from './services/email-verification.service';

describe('AuthController', () => {
  let controller: AuthController;
  let module: TestingModule;
  let prisma: any;
  let secureAuth: any;
  let bruteForce: any;
  let enhancedJwt: any;
  let twoFactor: any;

  beforeEach(async () => {
    const moduleRef: TestingModule = await Test.createTestingModule({
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
              findFirst: jest.fn(),
              create: jest.fn(),
            },
            loginAttempt: {
              create: jest.fn().mockResolvedValue({}),
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
            logJwtEvent: jest.fn(),
            logSecurityError: jest.fn(),
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
            verifyTOTP: jest.fn(),
            confirm2FA: jest.fn(),
            enable2FA: jest.fn(),
            disable2FA: jest.fn(),
          },
        },
        {
          provide: AnomalyDetectionService,
          useValue: {
            analyzeUserBehavior: jest.fn().mockResolvedValue({ score: 0 }),
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
        {
          provide: TelegramUsernameHistoryService,
          useValue: {
            record: jest.fn(),
            recordIfChanged: jest.fn(),
            listForUser: jest.fn(),
          },
        },
        {
          provide: EmailVerificationService,
          useValue: {
            generateToken: jest.fn().mockReturnValue('token'),
            expiresAt: jest.fn().mockReturnValue(new Date()),
            issueForUser: jest.fn(),
            verify: jest.fn(),
          },
        },
      ],
    }).compile();

    module = moduleRef;
    controller = module.get<AuthController>(AuthController);
    prisma = module.get(PrismaService);
    secureAuth = module.get(SecureAuthService);
    bruteForce = module.get(BruteForceService);
    enhancedJwt = module.get(EnhancedJwtService);
    twoFactor = module.get(TwoFactorAuthService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('login (2FA gate)', () => {
    const metadata = { get: jest.fn().mockReturnValue(undefined) } as any;
    const credentials = {
      email: 'user@example.com',
      password: 'SuperSecret123!',
    };

    beforeEach(() => {
      jest.clearAllMocks();
      metadata.get.mockReturnValue(undefined);
      bruteForce.isBlocked.mockResolvedValue(false);
      secureAuth.authenticateUser.mockResolvedValue({
        success: true,
        user: { id: 'u1', email: 'user@example.com' },
      });
    });

    // SECURITY_REVIEW #5 (частичная мера): 2FA проверяется ДО выпуска токенов,
    // поэтому токены/сессия НЕ создаются для аккаунта с включённой 2FA.
    it('does not mint tokens or session when 2FA is enabled', async () => {
      prisma.user.findUnique.mockResolvedValue({
        id: 'u1',
        twoFactorEnabled: true,
      });

      const result = await controller.login(credentials, metadata);

      expect(result).toEqual({
        accessToken: '2FA_REQUIRED',
        refreshToken: '2FA_REQUIRED',
      });
      expect(enhancedJwt.generateTokens).not.toHaveBeenCalled();
      expect(prisma.loginAttempt.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            success: false,
            failureReason: '2fa_required',
          }),
        }),
      );
    });

    it('issues token pair when 2FA is disabled', async () => {
      prisma.user.findUnique.mockResolvedValue({
        id: 'u1',
        twoFactorEnabled: false,
      });
      enhancedJwt.generateTokens.mockResolvedValue({
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
      });

      const result = await controller.login(credentials, metadata);

      expect(result).toEqual({
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
      });
      expect(enhancedJwt.generateTokens).toHaveBeenCalledWith(
        'u1',
        'user@example.com',
        expect.objectContaining({ ipAddress: expect.any(String) }),
      );
    });
  });

  describe('verify2FA', () => {
    const principal = { userId: 'u1' } as any;

    beforeEach(() => {
      jest.clearAllMocks();
    });

    it('rejects malformed 2FA token', async () => {
      await expect(
        controller.verify2FA({ token: 'toolongtokenvalue' } as any, principal),
      ).rejects.toBeInstanceOf(RpcException);
      expect(enhancedJwt.generateTokens).not.toHaveBeenCalled();
    });

    it('returns failure without tokens for an invalid TOTP code', async () => {
      prisma.user.findUnique.mockResolvedValue({
        id: 'u1',
        email: 'user@example.com',
        twoFactorPendingSecret: null,
        twoFactorSecret: 'secret',
      });
      twoFactor.verifyTOTP.mockReturnValue(false);

      const result = await controller.verify2FA(
        { token: '123456' } as any,
        principal,
      );

      expect(result.success).toBe(false);
      expect(result.accessToken).toBe('');
      expect(result.refreshToken).toBe('');
      expect(enhancedJwt.generateTokens).not.toHaveBeenCalled();
    });

    it('issues token pair on a valid TOTP code', async () => {
      prisma.user.findUnique.mockResolvedValue({
        id: 'u1',
        email: 'user@example.com',
        twoFactorPendingSecret: null,
        twoFactorSecret: 'secret',
      });
      twoFactor.verifyTOTP.mockReturnValue(true);
      enhancedJwt.generateTokens.mockResolvedValue({
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
      });

      const result = await controller.verify2FA(
        { token: '123456' } as any,
        principal,
      );

      expect(result.success).toBe(true);
      expect(result.accessToken).toBe('access-token');
      expect(result.refreshToken).toBe('refresh-token');
    });
  });
});
