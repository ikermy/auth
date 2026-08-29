import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../prisma.service';
import { SecurityLoggerService } from '../security-logger.service';
import * as crypto from 'crypto';
import * as QRCode from 'qrcode';

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

  // Генерация секретного ключа для 2FA в Base32 (RFC 4226/6238)
  generateSecret(): string {
    const bytes = crypto.randomBytes(20);
    return this.toBase32(bytes);
  }

  // Конвертация в Base32
  private toBase32(bytes: Buffer): string {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = 0;
    let value = 0;
    let output = '';

    for (let i = 0; i < bytes.length; i++) {
      value = (value << 8) | bytes[i];
      bits += 8;

      while (bits >= 5) {
        output += alphabet[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }

    if (bits > 0) {
      output += alphabet[(value << (5 - bits)) & 31];
    }

    return output;
  }

  // Генерация QR кода для Google Authenticator
  async generateQRCode(
    userId: string,
    email: string,
    secret: string,
  ): Promise<string> {
    // Валидация входных данных
    if (!userId || userId.trim().length === 0 || userId.length > 100) {
      throw new Error('Invalid user ID');
    }

    if (!email || email.trim().length === 0 || email.length > 255) {
      throw new Error('Invalid email');
    }

    if (!secret || secret.trim().length === 0 || secret.length > 100) {
      throw new Error('Invalid secret');
    }

    const otpauth = `otpauth://totp/${this.totpConfig.issuer}:${email}?secret=${secret}&issuer=${this.totpConfig.issuer}&algorithm=${this.totpConfig.algorithm}&digits=${this.totpConfig.digits}&period=${this.totpConfig.period}`;

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

  // Включение 2FA для пользователя
  async enable2FA(
    userId: string,
    secret?: string,
  ): Promise<{
    qrCode: string;
    backupCodes: string[];
  }> {
    // Валидация входных данных
    if (!userId || userId.trim().length === 0 || userId.length > 100) {
      throw new Error('Invalid user ID');
    }

    const generatedSecret = secret || this.generateSecret();
    if (
      !generatedSecret ||
      generatedSecret.trim().length === 0 ||
      generatedSecret.length > 100
    ) {
      throw new Error('Invalid secret');
    }

    try {
      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new Error('User not found');
      }

      const qrCode = await this.generateQRCode(
        userId,
        user.email,
        generatedSecret,
      );

      const backupCodes = this.generateBackupCodes();

      await this.prismaService.user.update({
        where: { id: userId },
        data: {
          twoFactorEnabled: true,
          twoFactorSecret: generatedSecret,
          backupCodes,
        },
      });

      this.securityLogger.logSuccess(
        'localhost',
        '2FA_ENABLED',
        `User: ${userId}`,
      );

      return { qrCode, backupCodes };
    } catch (error) {
      this.securityLogger.logSecurityError(
        '2FA_ENABLE_ERROR',
        `Failed to enable 2FA for user ${userId}: ${(error as Error).message}`,
      );
      throw error;
    }
  }

  // Отключение 2FA для пользователя
  async disable2FA(userId: string): Promise<boolean> {
    // Валидация входных данных
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

  // Проверка TOTP токена
  verifyTOTP(secret: string, token: string): boolean {
    // Валидация входных данных
    if (!secret || secret.trim().length === 0 || secret.length > 100) {
      return false;
    }

    if (!token || token.trim().length === 0 || token.length > 10) {
      return false;
    }

    // Используем crypto.randomBytes для получения случайного времени
    // чтобы избежать timing attacks
    const timeBuffer = crypto.randomBytes(4);
    const randomOffset = timeBuffer.readUInt32BE(0) % 1000; // Случайное смещение до 1 секунды

    const now = Math.floor(Date.now() / 1000) + randomOffset;
    const window = 1; // Допускаем отклонение в 1 период (30 секунд)

    // Используем timing-safe сравнение
    let isValid = false;
    for (let i = -window; i <= window; i++) {
      const time = now + i * this.totpConfig.period;
      const expectedToken = this.generateTOTP(secret, time);

      // Используем crypto.timingSafeEqual для предотвращения timing attacks
      if (token.length === expectedToken.length) {
        const tokenBuffer = Buffer.from(token, 'utf8');
        const expectedBuffer = Buffer.from(expectedToken, 'utf8');
        if (crypto.timingSafeEqual(tokenBuffer, expectedBuffer)) {
          isValid = true;
          break;
        }
      }
    }

    return isValid;
  }

  // Проверка backup кода
  async verifyBackupCode(userId: string, backupCode: string): Promise<boolean> {
    // Валидация входных данных
    if (!userId || userId.trim().length === 0 || userId.length > 100) {
      return false;
    }

    if (
      !backupCode ||
      backupCode.trim().length === 0 ||
      backupCode.length > 10
    ) {
      return false;
    }

    try {
      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
      });

      if (!user || !user.backupCodes) {
        return false;
      }

      const codes = user.backupCodes;

      // Timing-safe проверка backup кода
      let isValid = false;
      for (const code of codes) {
        if (backupCode.length === code.length) {
          const backupBuffer = Buffer.from(backupCode, 'utf8');
          const codeBuffer = Buffer.from(code, 'utf8');
          if (crypto.timingSafeEqual(backupBuffer, codeBuffer)) {
            isValid = true;
            break;
          }
        }
      }

      if (isValid) {
        // Удаляем использованный код
        const updatedCodes = codes.filter((code) => {
          if (backupCode.length === code.length) {
            const backupBuffer = Buffer.from(backupCode, 'utf8');
            const codeBuffer = Buffer.from(code, 'utf8');
            return !crypto.timingSafeEqual(backupBuffer, codeBuffer);
          }
          return true;
        });

        await this.prismaService.user.update({
          where: { id: userId },
          data: { backupCodes: updatedCodes },
        });
      }

      return isValid;
    } catch (error) {
      this.securityLogger.logSecurityError(
        '2FA_BACKUP_CODE_ERROR',
        `Failed to verify backup code for user ${userId}: ${(error as Error).message}`,
      );
      return false;
    }
  }

  // Генерация TOTP кода
  private generateTOTP(secret: string, time: number): string {
    try {
      // Валидация входных данных
      if (!secret || typeof secret !== 'string' || secret.length > 100) {
        throw new Error('Invalid secret for TOTP generation');
      }

      if (!time || typeof time !== 'number' || time < 0 || time > 9999999999) {
        throw new Error('Invalid time for TOTP generation');
      }

      const counter = Math.floor(time / this.totpConfig.period);
      const counterBuffer = Buffer.alloc(8);
      counterBuffer.writeBigUInt64BE(BigInt(counter), 0);

      const key = Buffer.from(secret, 'base64');
      const hmac = crypto.createHmac('sha256', key);
      hmac.update(counterBuffer);
      const hash = hmac.digest();

      const offset = hash[hash.length - 1] & 0xf;
      const code =
        ((hash[offset] & 0x7f) << 24) |
        ((hash[offset + 1] & 0xff) << 16) |
        ((hash[offset + 2] & 0xff) << 8) |
        (hash[offset + 3] & 0xff);

      return (code % Math.pow(10, this.totpConfig.digits))
        .toString()
        .padStart(this.totpConfig.digits, '0');
    } catch (error) {
      this.securityLogger.logSecurityError(
        'TOTP_GENERATION_ERROR',
        `Failed to generate TOTP: ${(error as Error).message}`,
      );
      throw error;
    }
  }

  // Генерация backup кодов
  private generateBackupCodes(): string[] {
    const codes: string[] = [];
    for (let i = 0; i < 10; i++) {
      // Используем более безопасный диапазон: 8 цифр
      const code = crypto.randomInt(10000000, 99999999).toString();
      codes.push(code);
    }
    return codes;
  }
}
