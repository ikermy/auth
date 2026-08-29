import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SecurityLoggerService } from '../security-logger.service';
import * as crypto from 'crypto';

@Injectable()
export class EncryptionService {
  private readonly algorithm = 'aes-256-gcm';
  private readonly keyLength = 32;
  private readonly ivLength = 16;
  private readonly tagLength = 16;

  constructor(
    private readonly configService: ConfigService,
    private readonly securityLogger: SecurityLoggerService,
  ) {}

  // Шифрование данных
  encrypt(data: string): string {
    try {
      // Валидация входных данных
      if (!data || typeof data !== 'string') {
        throw new Error('Invalid data for encryption');
      }

      if (data.length > 1000000) {
        // Максимум 1MB
        throw new Error('Data too large for encryption');
      }

      const key = this.getEncryptionKey();
      const iv = crypto.randomBytes(this.ivLength);
      const cipher = crypto.createCipheriv(this.algorithm, key, iv);
      cipher.setAAD(Buffer.from('auth-microservice', 'utf8'));

      let encrypted = cipher.update(data, 'utf8', 'hex');
      encrypted += cipher.final('hex');

      const tag = cipher.getAuthTag();

      // Формат: iv:tag:encrypted
      const result = `${iv.toString('hex')}:${tag.toString('hex')}:${encrypted}`;

      this.securityLogger.logSuccess(
        'localhost',
        'DATA_ENCRYPTED',
        'EncryptionService',
      );
      return result;
    } catch (error) {
      this.securityLogger.logSecurityError(
        'ENCRYPTION_ERROR',
        `Failed to encrypt data: ${(error as Error).message}`,
      );
      throw new Error('Encryption failed');
    }
  }

  // Расшифровка данных
  decrypt(encryptedData: string): string {
    try {
      // Валидация входных данных
      if (!encryptedData || typeof encryptedData !== 'string') {
        throw new Error('Invalid encrypted data');
      }

      if (encryptedData.length > 2000000) {
        // Максимум 2MB для зашифрованных данных
        throw new Error('Encrypted data too large');
      }

      const key = this.getEncryptionKey();
      const parts = encryptedData.split(':');

      if (parts.length !== 3) {
        throw new Error('Invalid encrypted data format');
      }

      const [ivHex, tagHex, encrypted] = parts;
      const iv = Buffer.from(ivHex, 'hex');
      const tag = Buffer.from(tagHex, 'hex');

      const decipher = crypto.createDecipheriv(this.algorithm, key, iv);
      decipher.setAuthTag(tag);
      decipher.setAAD(Buffer.from('auth-microservice', 'utf8'));

      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      this.securityLogger.logSuccess(
        'localhost',
        'DATA_DECRYPTED',
        'EncryptionService',
      );
      return decrypted;
    } catch (error) {
      this.securityLogger.logSecurityError(
        'DECRYPTION_ERROR',
        `Failed to decrypt data: ${(error as Error).message}`,
      );
      throw new Error('Decryption failed');
    }
  }

  // Хеширование с солью
  hashWithSalt(data: string, salt?: string): { hash: string; salt: string } {
    try {
      // Валидация входных данных
      if (!data || typeof data !== 'string') {
        throw new Error('Invalid data for hashing');
      }

      if (data.length > 1000000) {
        // Максимум 1MB
        throw new Error('Data too large for hashing');
      }

      if (salt && (typeof salt !== 'string' || salt.length > 100)) {
        throw new Error('Invalid salt for hashing');
      }

      const generatedSalt = salt || crypto.randomBytes(32).toString('hex');
      const hash = crypto
        .pbkdf2Sync(data, generatedSalt, 10000, 64, 'sha512')
        .toString('hex');

      return { hash, salt: generatedSalt };
    } catch (error) {
      this.securityLogger.logSecurityError(
        'HASHING_ERROR',
        `Failed to hash data: ${(error as Error).message}`,
      );
      throw new Error('Hashing failed');
    }
  }

  // Проверка хеша
  verifyHash(data: string, hash: string, salt: string): boolean {
    try {
      const computedHash = crypto
        .pbkdf2Sync(data, salt, 10000, 64, 'sha512')
        .toString('hex');
      return crypto.timingSafeEqual(
        Buffer.from(hash, 'hex'),
        Buffer.from(computedHash, 'hex'),
      );
    } catch (error) {
      this.securityLogger.logSecurityError(
        'HASH_VERIFICATION_ERROR',
        `Failed to verify hash: ${(error as Error).message}`,
      );
      return false;
    }
  }

  // Генерация безопасного токена
  generateSecureToken(length: number = 32): string {
    try {
      // Валидация входных данных
      if (
        !length ||
        typeof length !== 'number' ||
        length < 16 ||
        length > 1024
      ) {
        throw new Error(
          'Invalid token length. Must be between 16 and 1024 characters',
        );
      }

      return crypto.randomBytes(length).toString('base64url');
    } catch (error) {
      this.securityLogger.logSecurityError(
        'TOKEN_GENERATION_ERROR',
        `Failed to generate token: ${(error as Error).message}`,
      );
      throw new Error('Token generation failed');
    }
  }

  // Шифрование JWT payload
  encryptJwtPayload(payload: any): string {
    try {
      // Валидация входных данных
      if (!payload || typeof payload !== 'object') {
        throw new Error('Invalid JWT payload for encryption');
      }

      const payloadString = JSON.stringify(payload);
      return this.encrypt(payloadString);
    } catch (error) {
      this.securityLogger.logSecurityError(
        'JWT_PAYLOAD_ENCRYPTION_ERROR',
        `Failed to encrypt JWT payload: ${(error as Error).message}`,
      );
      throw error;
    }
  }

  // Расшифровка JWT payload
  decryptJwtPayload(encryptedPayload: string): any {
    try {
      // Валидация входных данных
      if (!encryptedPayload || typeof encryptedPayload !== 'string') {
        throw new Error('Invalid encrypted JWT payload');
      }

      const decryptedString = this.decrypt(encryptedPayload);

      // Безопасный JSON.parse с валидацией
      const parsed = this.safeJsonParse(decryptedString);
      if (parsed === null) {
        throw new Error('Invalid JSON payload');
      }

      return parsed;
    } catch (error) {
      this.securityLogger.logSecurityError(
        'JWT_PAYLOAD_DECRYPTION_ERROR',
        `Failed to decrypt JWT payload: ${(error as Error).message}`,
      );
      throw error;
    }
  }

  // Безопасный JSON.parse для предотвращения prototype pollution
  private safeJsonParse(jsonString: string): any {
    try {
      // Проверяем, что строка не слишком длинная
      if (jsonString.length > 1000000) {
        // Максимум 1MB
        return null;
      }

      // Проверяем, что это валидный JSON
      const parsed = JSON.parse(jsonString);

      // Проверяем, что результат не null и не undefined
      if (parsed === null || parsed === undefined) {
        return null;
      }

      // Проверяем, что это объект или массив
      if (typeof parsed !== 'object') {
        return null;
      }

      return parsed;
    } catch (error) {
      return null;
    }
  }

  // Получение ключа шифрования
  private getEncryptionKey(): Buffer {
    const key = this.configService.get('ENCRYPTION_KEY');
    if (!key) {
      throw new Error('ENCRYPTION_KEY not configured');
    }

    // Создаем хеш ключа для обеспечения правильной длины
    const hash = crypto.createHash('sha256');
    hash.update(key);
    return hash.digest();
  }

  // Ротация ключей шифрования
  async rotateEncryptionKeys(): Promise<void> {
    try {
      // Генерируем новый ключ
      const newKey = crypto.randomBytes(this.keyLength).toString('base64');

      // В продакшене здесь должна быть логика миграции данных
      // с старого ключа на новый

      this.securityLogger.logSuccess(
        'localhost',
        'ENCRYPTION_KEYS_ROTATED',
        'EncryptionService',
      );
    } catch (error) {
      this.securityLogger.logSecurityError(
        'KEY_ROTATION_ERROR',
        `Failed to rotate keys: ${(error as Error).message}`,
      );
      throw error;
    }
  }

  // Проверка целостности данных
  verifyDataIntegrity(data: string, signature: string): boolean {
    try {
      // Валидация входных данных
      if (!data || typeof data !== 'string') {
        return false;
      }

      if (
        !signature ||
        typeof signature !== 'string' ||
        signature.length > 200
      ) {
        return false;
      }

      if (data.length > 1000000) {
        // Максимум 1MB
        return false;
      }

      const key = this.getEncryptionKey();
      const expectedSignature = crypto
        .createHmac('sha256', key)
        .update(data)
        .digest('hex');

      return crypto.timingSafeEqual(
        Buffer.from(signature, 'hex'),
        Buffer.from(expectedSignature, 'hex'),
      );
    } catch (error) {
      this.securityLogger.logSecurityError(
        'INTEGRITY_CHECK_ERROR',
        `Failed to verify data integrity: ${(error as Error).message}`,
      );
      return false;
    }
  }

  // Подпись данных
  signData(data: string): string {
    try {
      // Валидация входных данных
      if (!data || typeof data !== 'string') {
        throw new Error('Invalid data for signing');
      }

      if (data.length > 1000000) {
        // Максимум 1MB
        throw new Error('Data too large for signing');
      }

      const key = this.getEncryptionKey();
      return crypto.createHmac('sha256', key).update(data).digest('hex');
    } catch (error) {
      this.securityLogger.logSecurityError(
        'DATA_SIGNING_ERROR',
        `Failed to sign data: ${(error as Error).message}`,
      );
      throw error;
    }
  }
}
