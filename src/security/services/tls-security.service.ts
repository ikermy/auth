/* eslint-disable @typescript-eslint/no-unsafe-argument */
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { SecurityLoggerService } from '../security-logger.service';

@Injectable()
export class TlsSecurityService {
  constructor(
    private readonly configService: ConfigService,
    private readonly securityLogger: SecurityLoggerService,
  ) {}

  // Получение TLS credentials для gRPC сервера
  getTlsCredentials() {
    try {
      const certPath = this.configService.get(
        'TLS_CERT_PATH',
        './certs/server.crt',
      );
      const keyPath = this.configService.get(
        'TLS_KEY_PATH',
        './certs/server.key',
      );
      const caPath = this.configService.get('TLS_CA_PATH', './certs/ca.crt');

      // Валидация путей к сертификатам
      if (!certPath || certPath.trim().length === 0 || certPath.length > 500) {
        throw new Error('Invalid certificate path');
      }

      if (!keyPath || keyPath.trim().length === 0 || keyPath.length > 500) {
        throw new Error('Invalid key path');
      }

      if (!caPath || caPath.trim().length === 0 || caPath.length > 500) {
        throw new Error('Invalid CA path');
      }

      // Проверяем существование файлов перед чтением
      const fullCertPath = join(process.cwd(), certPath);
      const fullKeyPath = join(process.cwd(), keyPath);
      const fullCaPath = join(process.cwd(), caPath);

      if (
        !existsSync(fullCertPath) ||
        !existsSync(fullKeyPath) ||
        !existsSync(fullCaPath)
      ) {
        this.securityLogger.logSecurityError(
          'TLS_CREDENTIALS_ERROR',
          'TLS certificate files not found',
        );
        throw new Error('TLS configuration incomplete');
      }

      const cert = readFileSync(fullCertPath);
      const key = readFileSync(fullKeyPath);
      const ca = readFileSync(fullCaPath);

      this.securityLogger.logSuccess(
        'localhost',
        'TLS_CREDENTIALS_LOADED',
        'TlsSecurityService',
      );

      return {
        cert,
        key,
        ca,
        checkServerIdentity: () => undefined, // Отключаем проверку hostname для внутренних сервисов
      };
    } catch (error) {
      this.securityLogger.logSecurityError(
        'TLS_CREDENTIALS_ERROR',
        `Failed to load TLS credentials: ${(error as Error).message}`,
      );
      throw new Error('TLS configuration incomplete');
    }
  }

  // Проверка TLS конфигурации
  validateTlsConfig(): boolean {
    const requiredVars = [
      'TLS_CERT_PATH',
      'TLS_KEY_PATH',
      'TLS_CA_PATH',
      'TLS_ENABLED',
    ];

    const missingVars = requiredVars.filter(
      (varName) => !this.configService.get(varName),
    );

    if (missingVars.length > 0) {
      this.securityLogger.logSecurityError(
        'TLS_CONFIG_ERROR',
        `Missing TLS variables: ${missingVars.join(', ')}`,
      );
      return false;
    }

    return true;
  }

  // Получение TLS порта
  getTlsPort(): number {
    const port = this.configService.get('TLS_PORT', 50052);

    // Валидация порта
    if (!port || port < 1 || port > 65535) {
      throw new Error('Invalid TLS port configuration');
    }

    return port;
  }

  // Проверка необходимости TLS
  isTlsEnabled(): boolean {
    return this.configService.get('TLS_ENABLED', 'false') === 'true';
  }
}
