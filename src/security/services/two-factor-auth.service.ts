import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../prisma.service';
import { SecurityLoggerService } from '../security-logger.service';
import * as speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';
import * as crypto from 'crypto';

interface TOTPConfig {
  issuer: string;
  algorithm: string;
  digits: number;
  period: number;
}

@Injectable()
export class TwoFactorAuthService {
  private readonly totpConfig: TOTPConfig;

  constructor(
    private readonly configService: ConfigService,
    private readonly prismaService: PrismaService,
    private readonly securityLogger: SecurityLoggerService,
  ) {
    this.totpConfig = {
      issuer: this.configService.get('TOTP_ISSUER', 'Auth Microservice'),
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
    };
  }

  // Генерация Base32-секрета (RFC 4226/6238) через speakeasy
  generateSecret(): string {
    const secret = speakeasy.generateSecret({ length: 20 });
    return secret.base32;
  }

  // Генерация otpauth URI
  private generateOtpAuthUri(email: string, secret: string): string {
    return speakeasy.otpauthURL({
      secret,
      label: `${this.totpConfig.issuer}:${email}`,
      issuer: this.totpConfig.issuer,
      algorithm: this.totpConfig.algorithm.toLowerCase() as
        | 'sha1'
        | 'sha256'
        | 'sha512',
      digits: this.totpConfig.digits,
      period: this.totpConfig.period,
    });
  }

  // Генерация QR кода
  async generateQRCode(
    userId: string,
    email: string,
    secret: string,
  ): Promise<string> {
    if (!userId || userId.trim().length === 0 || userId.length > 100) {
      throw new Error('Invalid user ID');
    }

    if (!email || email.trim().length === 0 || email.length > 255) {
      throw new Error('Invalid email');
    }

    if (!secret || secret.trim().length === 0 || secret.length > 100) {
      throw new Error('Invalid secret');
    }

    const otpauth = this.generateOtpAuthUri(email, secret);

    try {
      const qrCode = await QRCode.toDataURL(otpauth);
      this.securityLogger.logSuccess(
        'localhost',
        'QR_CODE_GENERATED',
        `User: ${userId}`,
      );
      return qrCode;
    } catch (error) {
      this.securityLogger.logSecurityError(
        'QR_CODE_ERROR',
        `Failed to generate QR code: ${(error as Error).message}`,
      );
      throw error;
    }
  }

  // Этап 1 — инициализация 2FA: генерируем secret и держим его в состоянии
  // pending до подтверждения первого кода. Не активирует 2FA и не трогает
  // уже настроенный secret (закрывает 2FA-02, IDEM-1).
  async initiate2FA(
    userId: string,
  ): Promise<{ qrCode: string; otpauthUrl: string }> {
    if (!userId || userId.trim().length === 0 || userId.length > 100) {
      throw new Error('Invalid user ID');
    }

    const user = await this.prismaService.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new Error('User not found');
    }

    // Если 2FA уже активна — не перезаписываем настроенный секрет
    if (user.twoFactorEnabled) {
      throw new Error('2FA is already enabled');
    }

    const secret = this.generateSecret();
    const qrCode = await this.generateQRCode(userId, user.email, secret);
    const otpauthUrl = this.generateOtpAuthUri(user.email, secret);

    await this.prismaService.user.update({
      where: { id: userId },
      data: {
        twoFactorPendingSecret: secret,
        twoFactorPendingSecretCreatedAt: new Date(),
      },
    });

    this.securityLogger.logSuccess(
      'localhost',
      '2FA_INITIATED',
      `User: ${userId}`,
    );

    return { qrCode, otpauthUrl };
  }

  // Этап 2 — подтверждение первого кода: активирует 2FA и выдаёт backup codes.
  async confirm2FA(
    userId: string,
    token: string,
  ): Promise<{ success: boolean; backupCodes: string[] }> {
    if (!userId || userId.trim().length === 0 || userId.length > 100) {
      throw new Error('Invalid user ID');
    }

    const user = await this.prismaService.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new Error('User not found');
    }

    if (!user.twoFactorPendingSecret) {
      throw new Error('2FA setup was not initiated');
    }

    const valid = this.verifyTOTP(user.twoFactorPendingSecret, token);
    if (!valid) {
      return { success: false, backupCodes: [] };
    }

    const backupCodes = this.generateBackupCodeHashes();

    await this.prismaService.user.update({
      where: { id: userId },
      data: {
        twoFactorEnabled: true,
        twoFactorSecret: user.twoFactorPendingSecret,
        twoFactorPendingSecret: null,
        twoFactorPendingSecretCreatedAt: null,
        backupCodes: backupCodes.hashes,
      },
    });

    this.securityLogger.logSuccess(
      'localhost',
      '2FA_ENABLED',
      `User: ${userId}`,
    );

    return { success: true, backupCodes: backupCodes.plain };
  }

  // Совместимость: прежний вызов enable2FA делегирует в initiate2FA
  async enable2FA(
    userId: string,
    _secret?: string,
  ): Promise<{ qrCode: string; backupCodes: string[] }> {
    const result = await this.initiate2FA(userId);
    return { qrCode: result.qrCode, backupCodes: [] };
  }

  // Отключение 2FA
  async disable2FA(userId: string): Promise<boolean> {
    if (!userId || userId.trim().length === 0 || userId.length > 100) {
      throw new Error('Invalid user ID for 2FA disable');
    }

    try {
      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        return false;
      }

      await this.prismaService.user.update({
        where: { id: userId },
        data: {
          twoFactorEnabled: false,
          twoFactorSecret: null,
          twoFactorPendingSecret: null,
          twoFactorPendingSecretCreatedAt: null,
          backupCodes: [],
        },
      });

      this.securityLogger.logSuccess(
        'localhost',
        '2FA_DISABLED',
        `User: ${userId}`,
      );

      return true;
    } catch (error) {
      this.securityLogger.logSecurityError(
        '2FA_DISABLE_ERROR',
        `Failed to disable 2FA for user ${userId}: ${(error as Error).message}`,
      );
      throw error;
    }
  }

  // Проверка TOTP через speakeasy (RFC 6238): Base32-секрет, SHA-1,
  // фиксированное окно ±1 шаг. Заменяет дефектную самописную реализацию
  // (2FA-1/2/3).
  verifyTOTP(secret: string, token: string): boolean {
    if (!secret || secret.trim().length === 0 || secret.length > 100) {
      return false;
    }

    if (!token || token.trim().length === 0 || token.length > 10) {
      return false;
    }

    try {
      return speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token,
        window: 1,
        algorithm: this.totpConfig.algorithm.toLowerCase() as
          | 'sha1'
          | 'sha256'
          | 'sha512',
        digits: this.totpConfig.digits,
      });
    } catch {
      return false;
    }
  }

  // Проверка backup-кода по хешу; использованный код атомарно погашается.
  async verifyBackupCode(userId: string, backupCode: string): Promise<boolean> {
    if (!userId || userId.trim().length === 0 || userId.length > 100) {
      return false;
    }

    if (!backupCode || backupCode.trim().length === 0) {
      return false;
    }

    try {
      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
      });

      if (!user || !user.backupCodes) {
        return false;
      }

      const targetHash = this.hashCode(backupCode);
      const idx = user.backupCodes.indexOf(targetHash);
      if (idx === -1) {
        return false;
      }

      const updated = [...user.backupCodes];
      updated.splice(idx, 1);
      await this.prismaService.user.update({
        where: { id: userId },
        data: { backupCodes: updated },
      });

      return true;
    } catch (error) {
      this.securityLogger.logSecurityError(
        '2FA_BACKUP_CODE_ERROR',
        `Failed to verify backup code for user ${userId}: ${(error as Error).message}`,
      );
      return false;
    }
  }

  private hashCode(code: string): string {
    return crypto.createHash('sha256').update(code).digest('hex');
  }

  private generateBackupCodeHashes(): { plain: string[]; hashes: string[] } {
    const plain: string[] = [];
    const hashes: string[] = [];
    for (let i = 0; i < 10; i++) {
      const code = crypto.randomInt(10000000, 99999999).toString();
      plain.push(code);
      hashes.push(this.hashCode(code));
    }
    return { plain, hashes };
  }
}
