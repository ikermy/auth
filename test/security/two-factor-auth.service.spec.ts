import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { TwoFactorAuthService } from '../../src/security/services/two-factor-auth.service';
import { PrismaService } from '../../src/prisma.service';
import { SecurityLoggerService } from '../../src/security/security-logger.service';
import * as speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';
import * as crypto from 'crypto';

jest.mock('speakeasy', () => ({
  generateSecret: jest.fn(() => ({ base32: 'MOCKBASE32SECRET1234567890' })),
  otpauthURL: jest.fn(() => 'otpauth://totp/test:test@example.com?secret=MOCK'),
  totp: { verify: jest.fn(() => true) },
}));
jest.mock('qrcode', () => ({ toDataURL: jest.fn() }));

const hash = (code: string) =>
  crypto.createHash('sha256').update(code).digest('hex');

describe('TwoFactorAuthService', () => {
  let service: TwoFactorAuthService;
  let prismaService: PrismaService;
  let securityLogger: SecurityLoggerService;

  const mockUser = {
    id: '1',
    email: 'test@example.com',
    twoFactorSecret: null,
    twoFactorEnabled: false,
    twoFactorPendingSecret: null,
    twoFactorPendingSecretCreatedAt: null,
    backupCodes: [],
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TwoFactorAuthService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string, defaultValue?: any) => {
              const config = { TOTP_ISSUER: 'Test Auth Service' };
              return config[key as keyof typeof config] || defaultValue;
            }),
          },
        },
        {
          provide: PrismaService,
          useValue: {
            user: {
              findUnique: jest.fn(),
              update: jest.fn(),
            },
          } as any,
        },
        {
          provide: SecurityLoggerService,
          useValue: {
            logSecurityError: jest.fn(),
            logSuccess: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<TwoFactorAuthService>(TwoFactorAuthService);
    prismaService = module.get<PrismaService>(PrismaService);
    securityLogger = module.get<SecurityLoggerService>(SecurityLoggerService);

    (speakeasy.totp.verify as jest.Mock).mockReturnValue(true);
  });

  afterEach(() => jest.clearAllMocks());

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('initiate2FA', () => {
    it('should generate pending secret and QR, not enable 2FA', async () => {
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (prismaService.user.update as jest.Mock).mockResolvedValue(mockUser);
      (QRCode.toDataURL as jest.Mock).mockResolvedValue(
        'data:image/png;base64,test',
      );

      const result = await service.initiate2FA('1');

      expect(result.qrCode).toBeDefined();
      expect(result.otpauthUrl).toBeDefined();
      expect(prismaService.user.update).toHaveBeenCalledWith({
        where: { id: '1' },
        data: {
          twoFactorPendingSecret: expect.any(String),
          twoFactorPendingSecretCreatedAt: expect.any(Date),
        },
      });
    });

    it('should reject if 2FA already enabled', async () => {
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue({
        ...mockUser,
        twoFactorEnabled: true,
      });

      await expect(service.initiate2FA('1')).rejects.toThrow(
        '2FA is already enabled',
      );
    });

    it('should fail if user not found', async () => {
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(null);

      await expect(service.initiate2FA('1')).rejects.toThrow('User not found');
    });
  });

  describe('confirm2FA', () => {
    it('should activate 2FA on valid first code and return backup codes', async () => {
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue({
        ...mockUser,
        twoFactorPendingSecret: 'MOCKBASE32SECRET1234567890',
      });
      (prismaService.user.update as jest.Mock).mockResolvedValue(mockUser);

      const result = await service.confirm2FA('1', '123456');

      expect(result.success).toBe(true);
      expect(result.backupCodes).toHaveLength(10);
      expect(prismaService.user.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: '1' },
          data: expect.objectContaining({
            twoFactorEnabled: true,
            twoFactorPendingSecret: null,
            backupCodes: expect.any(Array),
          }),
        }),
      );
    });

    it('should return failure on invalid code', async () => {
      (speakeasy.totp.verify as jest.Mock).mockReturnValue(false);
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue({
        ...mockUser,
        twoFactorPendingSecret: 'MOCKBASE32SECRET1234567890',
      });

      const result = await service.confirm2FA('1', '000000');

      expect(result.success).toBe(false);
      expect(result.backupCodes).toHaveLength(0);
    });
  });

  describe('disable2FA', () => {
    it('should disable 2FA for user', async () => {
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (prismaService.user.update as jest.Mock).mockResolvedValue({
        ...mockUser,
        twoFactorEnabled: false,
      });

      await service.disable2FA('1');

      expect(prismaService.user.update).toHaveBeenCalledWith({
        where: { id: '1' },
        data: {
          twoFactorSecret: null,
          twoFactorEnabled: false,
          twoFactorPendingSecret: null,
          twoFactorPendingSecretCreatedAt: null,
          backupCodes: [],
        },
      });
      expect(securityLogger.logSuccess).toHaveBeenCalledWith(
        'localhost',
        '2FA_DISABLED',
        'User: 1',
      );
    });
  });

  describe('verifyTOTP', () => {
    it('should delegate to speakeasy', () => {
      const result = service.verifyTOTP('MOCKBASE32SECRET1234567890', '123456');

      expect(speakeasy.totp.verify).toHaveBeenCalled();
      expect(result).toBe(true);
    });

    it('should return false for invalid token', () => {
      const result = service.verifyTOTP('secret', '');

      expect(result).toBe(false);
    });
  });

  describe('verifyBackupCode', () => {
    it('should verify and burn valid backup code', async () => {
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue({
        ...mockUser,
        backupCodes: [hash('backup123'), hash('backup456')],
      });
      (prismaService.user.update as jest.Mock).mockResolvedValue(mockUser);

      const result = await service.verifyBackupCode('1', 'backup123');

      expect(result).toBe(true);
      expect(prismaService.user.update).toHaveBeenCalled();
    });

    it('should fail with invalid backup code', async () => {
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue({
        ...mockUser,
        backupCodes: [hash('backup123')],
      });

      const result = await service.verifyBackupCode('1', 'invalid');

      expect(result).toBe(false);
    });

    it('should fail if user not found', async () => {
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(null);

      const result = await service.verifyBackupCode('1', 'backup123');

      expect(result).toBe(false);
    });
  });

  describe('generateSecret', () => {
    it('should generate base32 secret via speakeasy', () => {
      const secret = service.generateSecret();

      expect(speakeasy.generateSecret).toHaveBeenCalled();
      expect(secret).toBe('MOCKBASE32SECRET1234567890');
    });
  });
});
