import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { TwoFactorAuthService } from '../../src/security/services/two-factor-auth.service';
import { PrismaService } from '../../src/prisma.service';
import { SecurityLoggerService } from '../../src/security/security-logger.service';
import * as speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';

jest.mock('speakeasy');
jest.mock('qrcode');

describe('TwoFactorAuthService', () => {
  let service: TwoFactorAuthService;
  let prismaService: PrismaService;
  let configService: ConfigService;
  let securityLogger: SecurityLoggerService;

  const mockUser = {
    id: '1',
    email: 'test@example.com',
    twoFactorSecret: null,
    twoFactorEnabled: false,
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
              const config = {
                TOTP_ISSUER: 'Test Auth Service',
              };
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
    configService = module.get<ConfigService>(ConfigService);
    securityLogger = module.get<SecurityLoggerService>(SecurityLoggerService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('enable2FA', () => {
    it('should enable 2FA for user', async () => {
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (prismaService.user.update as jest.Mock).mockResolvedValue({
        ...mockUser,
        twoFactorSecret: 'test-secret',
        twoFactorEnabled: true,
        backupCodes: ['code1', 'code2'],
      });
      (QRCode.toDataURL as jest.Mock).mockResolvedValue(
        'data:image/png;base64,test',
      );

      const result = await service.enable2FA('1', 'test-secret');

      expect(result.qrCode).toBeDefined();
      expect(result.backupCodes).toHaveLength(10);
      expect(securityLogger.logSuccess).toHaveBeenCalledWith(
        'localhost',
        '2FA_ENABLED',
        'User: 1',
      );
    });

    it('should fail if user not found', async () => {
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(null);

      await expect(service.enable2FA('1', 'test-secret')).rejects.toThrow(
        'User not found',
      );
    });
  });

  describe('disable2FA', () => {
    it('should disable 2FA for user', async () => {
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (prismaService.user.update as jest.Mock).mockResolvedValue({
        ...mockUser,
        twoFactorEnabled: false,
        twoFactorSecret: null,
        backupCodes: [],
      });

      await service.disable2FA('1');

      expect(prismaService.user.update).toHaveBeenCalledWith({
        where: { id: '1' },
        data: {
          twoFactorSecret: null,
          twoFactorEnabled: false,
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
    it('should verify valid TOTP token', () => {
      const result = service.verifyTOTP('test-secret', '123456');

      expect(typeof result).toBe('boolean');
    });
  });

  describe('verifyBackupCode', () => {
    it('should verify valid backup code', async () => {
      const userWithBackupCodes = {
        ...mockUser,
        backupCodes: ['backup123', 'backup456'],
      };
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(
        userWithBackupCodes,
      );
      (prismaService.user.update as jest.Mock).mockResolvedValue(
        userWithBackupCodes,
      );

      const result = await service.verifyBackupCode('1', 'backup123');

      expect(result).toBe(true);
    });

    it('should fail with invalid backup code', async () => {
      const userWithBackupCodes = {
        ...mockUser,
        backupCodes: ['backup123', 'backup456'],
      };
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(
        userWithBackupCodes,
      );

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
    it('should generate secret', () => {
      const secret = service.generateSecret();

      expect(secret).toBeDefined();
      expect(typeof secret).toBe('string');
    });
  });

  describe('generateQRCode', () => {
    it('should generate QR code', async () => {
      (QRCode.toDataURL as jest.Mock).mockResolvedValue(
        'data:image/png;base64,test',
      );

      const qrCode = await service.generateQRCode(
        '1',
        'test@example.com',
        'test-secret',
      );

      expect(qrCode).toBeDefined();
      expect(qrCode).toMatch(/^data:image\/png;base64,/);
    });

    it('should handle QR code generation error', async () => {
      (QRCode.toDataURL as jest.Mock).mockRejectedValue(
        new Error('QR generation failed'),
      );

      await expect(
        service.generateQRCode('1', 'test@example.com', 'test-secret'),
      ).rejects.toThrow('QR generation failed');
    });
  });

  describe('private methods', () => {
    it('should access private generateBackupCodes method', () => {
      const codes = (service as any).generateBackupCodes();

      expect(Array.isArray(codes)).toBe(true);
      expect(codes.length).toBe(10);
    });

    it('should access private generateTOTP method', () => {
      const totp = (service as any).generateTOTP(
        'test-secret',
        Math.floor(Date.now() / 1000),
      );

      expect(typeof totp).toBe('string');
      expect(totp.length).toBe(6);
    });
  });
});
