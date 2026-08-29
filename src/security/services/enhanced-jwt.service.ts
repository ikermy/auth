import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { createClient, RedisClientType } from 'redis';
import { randomUUID } from 'crypto';
import { SecurityLoggerService } from '../security-logger.service';

interface JwtPayload {
  sub: string;
  email: string;
  jti: string; // JWT ID для отзыва токенов
  iat: number;
  exp: number;
  type: 'access' | 'refresh';
}

@Injectable()
export class EnhancedJwtService {
  private redisClient!: RedisClientType;

  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly securityLogger: SecurityLoggerService,
  ) {}

  async onModuleInit() {
    try {
      await this.initRedis();
    } catch (error) {
      this.securityLogger.logSecurityError(
        'ENHANCED_JWT_INIT_ERROR',
        `Failed to initialize EnhancedJwtService: ${(error as Error).message}`,
      );
      // В продакшене можно использовать fallback или перезапуск
    }
  }

  private async initRedis() {
    try {
      const redisConfig: any = {
        socket: {
          host: this.configService.get('REDIS_HOST', 'redis'),
          port: this.configService.get('REDIS_PORT', 6379),
        },
      };

      // Добавляем аутентификацию если указана
      const password = this.configService.get('REDIS_PASSWORD');
      const username = this.configService.get('REDIS_USERNAME');

      if (password) {
        redisConfig.password = password;
      }
      if (username) {
        redisConfig.username = username;
      }

      this.redisClient = createClient(redisConfig);

      try {
        await this.redisClient.connect();
        this.securityLogger.logRedisEvent(
          'CONNECTED',
          'EnhancedJwtService connected to Redis',
        );
      } catch (error) {
        this.securityLogger.logSecurityError(
          'REDIS_CONNECTION_FAILED',
          (error as Error).message,
        );
        // В продакшене можно использовать fallback или перезапуск
      }
    } catch (error) {
      this.securityLogger.logSecurityError(
        'REDIS_CONFIG_ERROR',
        `Failed to configure Redis: ${(error as Error).message}`,
      );
      throw error;
    }
  }

  // Генерация токенов с JTI
  async generateTokens(
    userId: string,
    email: string,
  ): Promise<{
    accessToken: string;
    refreshToken: string;
    accessTokenId: string;
    refreshTokenId: string;
  }> {
    try {
      // Валидация входных данных
      if (!userId || userId.trim().length === 0 || userId.length > 100) {
        throw new Error('Invalid user ID for token generation');
      }

      if (!email || email.trim().length === 0 || email.length > 255) {
        throw new Error('Invalid email for token generation');
      }

      const accessTokenId = randomUUID();
      const refreshTokenId = randomUUID();

      const accessPayload: JwtPayload = {
        sub: userId,
        email,
        jti: accessTokenId,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 15 * 60, // 15 минут
        type: 'access',
      };

      const refreshPayload: JwtPayload = {
        sub: userId,
        email,
        jti: refreshTokenId,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60, // 7 дней
        type: 'refresh',
      };

      const [accessToken, refreshToken] = await Promise.all([
        this.jwtService.signAsync(accessPayload),
        this.jwtService.signAsync(refreshPayload),
      ]);

      // Сохраняем метаданные токенов в Redis
      try {
        await Promise.all([
          this.storeTokenMetadata(accessTokenId, userId, 'access', 15 * 60),
          this.storeTokenMetadata(
            refreshTokenId,
            userId,
            'refresh',
            7 * 24 * 60 * 60,
          ),
        ]);
      } catch (error) {
        this.securityLogger.logSecurityError(
          'TOKEN_METADATA_SAVE_ERROR',
          `Failed to save token metadata: ${(error as Error).message}`,
        );
        // Продолжаем выполнение, так как токены уже созданы
      }

      this.securityLogger.logJwtEvent(
        'tokens_generated',
        `User: ${userId}, Access JTI: ${accessTokenId}`,
      );

      return {
        accessToken,
        refreshToken,
        accessTokenId,
        refreshTokenId,
      };
    } catch (error) {
      this.securityLogger.logSecurityError(
        'TOKEN_GENERATION_ERROR',
        `Failed to generate tokens: ${(error as Error).message}`,
      );
      throw error;
    }
  }

  // Верификация токена с проверкой отзыва
  async verifyToken(token: string): Promise<JwtPayload> {
    // Валидация входных данных
    if (!token || token.trim().length === 0 || token.length > 2000) {
      throw new Error('Invalid token for verification');
    }

    try {
      const payload = await this.jwtService.verifyAsync(token);

      // Проверяем, не отозван ли токен
      const isRevoked = await this.isTokenRevoked(payload.jti);
      if (isRevoked) {
        throw new Error('Token has been revoked');
      }

      return payload;
    } catch (error) {
      this.securityLogger.logJwtEvent(
        'token_verification_failed',
        `Error: ${(error as Error).message}`,
      );
      throw error;
    }
  }

  // Отзыв токена по JTI
  async revokeToken(jti: string): Promise<void> {
    // Валидация входных данных
    if (!jti || jti.trim().length === 0 || jti.length > 100) {
      throw new Error('Invalid JTI for token revocation');
    }

    try {
      await this.redisClient.setEx(`revoked:${jti}`, 7 * 24 * 60 * 60, '1');
      this.securityLogger.logJwtEvent('token_revoked', `JTI: ${jti}`);
    } catch (error) {
      this.securityLogger.logSecurityError(
        'TOKEN_REVOCATION_ERROR',
        `Failed to revoke token ${jti}: ${(error as Error).message}`,
      );
      throw error;
    }
  }

  // Отзыв всех токенов пользователя
  async revokeAllUserTokens(userId: string): Promise<void> {
    // Валидация входных данных
    if (!userId || userId.trim().length === 0 || userId.length > 100) {
      throw new Error('Invalid user ID for token revocation');
    }

    try {
      const pattern = `token_meta:*:${userId}`;
      const keys = await this.redisClient.keys(pattern);

      const revokePromises = keys.map(async (key) => {
        try {
          const jti = key.split(':')[1];
          await this.revokeToken(jti);
        } catch (error) {
          this.securityLogger.logSecurityError(
            'SINGLE_TOKEN_REVOCATION_ERROR',
            `Failed to revoke single token: ${(error as Error).message}`,
          );
          // Продолжаем с другими токенами
        }
      });

      await Promise.all(revokePromises);
      this.securityLogger.logJwtEvent(
        'all_user_tokens_revoked',
        `User: ${userId}`,
      );
    } catch (error) {
      this.securityLogger.logSecurityError(
        'ALL_TOKENS_REVOCATION_ERROR',
        `Failed to revoke all tokens for user ${userId}: ${(error as Error).message}`,
      );
      throw error;
    }
  }

  // Проверка отзыва токена
  private async isTokenRevoked(jti: string): Promise<boolean> {
    try {
      if (!jti || jti.trim().length === 0 || jti.length > 100) {
        return false;
      }

      const result = await this.redisClient.get(`revoked:${jti}`);
      return result !== null;
    } catch (error) {
      this.securityLogger.logSecurityError(
        'TOKEN_REVOCATION_CHECK_ERROR',
        `Failed to check token revocation: ${(error as Error).message}`,
      );
      return false;
    }
  }

  // Сохранение метаданных токена
  private async storeTokenMetadata(
    jti: string,
    userId: string,
    type: 'access' | 'refresh',
    ttl: number,
  ): Promise<void> {
    try {
      if (!jti || jti.trim().length === 0 || jti.length > 100) {
        throw new Error('Invalid JTI for metadata storage');
      }

      if (!userId || userId.trim().length === 0 || userId.length > 100) {
        throw new Error('Invalid user ID for metadata storage');
      }

      if (!type || !['access', 'refresh'].includes(type)) {
        throw new Error('Invalid token type for metadata storage');
      }

      if (!ttl || ttl <= 0 || ttl > 365 * 24 * 60 * 60) {
        // Максимум 1 год
        throw new Error('Invalid TTL for metadata storage');
      }

      const metadata = {
        userId,
        type,
        issuedAt: Date.now(),
        expiresAt: Date.now() + ttl * 1000,
      };

      await this.redisClient.setEx(
        `token_meta:${jti}:${userId}`,
        ttl,
        JSON.stringify(metadata),
      );
    } catch (error) {
      this.securityLogger.logSecurityError(
        'TOKEN_METADATA_STORAGE_ERROR',
        `Failed to store token metadata: ${(error as Error).message}`,
      );
      throw error;
    }
  }

  // Получение активных токенов пользователя
  async getUserActiveTokens(userId: string): Promise<
    Array<{
      jti: string;
      type: string;
      issuedAt: number;
      expiresAt: number;
    }>
  > {
    // Валидация входных данных
    if (!userId || userId.trim().length === 0 || userId.length > 100) {
      throw new Error('Invalid user ID for token retrieval');
    }

    try {
      const pattern = `token_meta:*:${userId}`;
      const keys = await this.redisClient.keys(pattern);

      const tokens = await Promise.all(
        keys.map(async (key) => {
          try {
            const metadata = await this.redisClient.get(key);
            const keyParts = key.split(':');

            // Валидация структуры ключа
            if (keyParts.length < 3) {
              this.securityLogger.logSecurityError(
                'INVALID_KEY_FORMAT',
                `Invalid key format: ${key}`,
              );
              return null;
            }

            const jti = keyParts[1];
            const revoked = await this.isTokenRevoked(jti);

            return revoked
              ? null
              : {
                  jti,
                  ...this.safeJsonParse((metadata as string) || '{}'),
                };
          } catch (error) {
            this.securityLogger.logSecurityError(
              'SINGLE_TOKEN_RETRIEVAL_ERROR',
              `Failed to retrieve single token: ${(error as Error).message}`,
            );
            return null;
          }
        }),
      );

      return tokens.filter(Boolean) as Array<{
        jti: string;
        type: string;
        issuedAt: number;
        expiresAt: number;
      }>;
    } catch (error) {
      this.securityLogger.logSecurityError(
        'TOKENS_RETRIEVAL_ERROR',
        `Failed to retrieve tokens for user ${userId}: ${(error as Error).message}`,
      );
      throw error;
    }
  }

  // Безопасный JSON.parse с валидацией
  private safeJsonParse(jsonString: string): any {
    try {
      // Проверяем, что строка не слишком длинная
      if (!jsonString || jsonString.length > 1000000) {
        // Максимум 1MB
        return {};
      }

      // Проверяем, что это валидный JSON
      const parsed = JSON.parse(jsonString);

      // Проверяем, что результат не null и не undefined
      if (parsed === null || parsed === undefined) {
        return {};
      }

      // Проверяем, что это объект
      if (typeof parsed !== 'object') {
        return {};
      }

      return parsed;
    } catch (error) {
      this.securityLogger.logSecurityError(
        'JSON_PARSE_ERROR',
        `Failed to parse JSON string: ${jsonString}, Error: ${(error as Error).message}`,
      );
      return {};
    }
  }
}
