import { Injectable } from '@nestjs/common';
import { createClient, RedisClientType } from 'redis';
import { ConfigService } from '@nestjs/config';
import { SecurityLoggerService } from '../security-logger.service';

@Injectable()
export class BruteForceService {
  private redisClient!: RedisClientType;

  constructor(
    private readonly configService: ConfigService,
    private readonly securityLogger: SecurityLoggerService,
  ) {}

  async onModuleInit() {
    try {
      await this.initRedis();
    } catch (error) {
      this.securityLogger.logSecurityError(
        'BRUTE_FORCE_INIT_ERROR',
        `Failed to initialize BruteForceService: ${(error as Error).message}`,
      );
      // В продакшене можно использовать fallback или перезапуск
    }
  }

  private async initRedis() {
    try {
      const redisConfig: {
        socket: {
          host: string;
          port: number;
        };
        password?: string;
        username?: string;
      } = {
        socket: {
          host: this.configService.get<string>('REDIS_HOST', 'redis'),
          port: this.configService.get<number>('REDIS_PORT', 6379),
        },
      };

      // Добавляем аутентификацию если указана
      const password = this.configService.get<string>('REDIS_PASSWORD');
      const username = this.configService.get<string>('REDIS_USERNAME');

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
          'BruteForceService connected to Redis',
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
        `Failed to configure Redis for BruteForceService: ${(error as Error).message}`,
      );
      throw error;
    }
  }

  // Проверка заблокирован ли IP или email
  async isBlocked(key: string): Promise<boolean> {
    // Валидация входных данных
    if (!key || key.trim().length === 0 || key.length > 200) {
      throw new Error('Invalid key for brute force check');
    }

    try {
      const attempts = await this.redisClient.get(`bf:${key}`);

      if (attempts === null) {
        return false;
      }

      const attemptsNum = parseInt(attempts as string);

      // Проверка на валидность числа
      if (isNaN(attemptsNum) || attemptsNum < 0) {
        return false;
      }

      return attemptsNum >= 5;
    } catch (error) {
      this.securityLogger.logSecurityError(
        'REDIS_BRUTE_FORCE_CHECK_ERROR',
        `Failed to check brute force status: ${(error as Error).message}`,
      );
      // В случае ошибки Redis, разрешаем доступ (fail-open)
      return false;
    }
  }

  // Увеличение счетчика неудачных попыток
  async recordFailedAttempt(key: string): Promise<void> {
    // Валидация входных данных
    if (!key || key.trim().length === 0 || key.length > 200) {
      throw new Error('Invalid key for brute force recording');
    }

    try {
      const current = await this.redisClient.incr(`bf:${key}`);
      await this.redisClient.expire(`bf:${key}`, 900); // 15 минут

      if (current === 5) {
        this.securityLogger.logSecurityError(
          'BRUTE_FORCE_DETECTED',
          `Key: ${key}`,
        );
      }
    } catch (error) {
      this.securityLogger.logSecurityError(
        'REDIS_BRUTE_FORCE_RECORD_ERROR',
        `Failed to record brute force attempt: ${(error as Error).message}`,
      );
      // В случае ошибки Redis, логируем но не блокируем
    }
  }

  // Очистка счетчика при успешной аутентификации
  async clearFailedAttempts(key: string): Promise<void> {
    // Валидация входных данных
    if (!key || key.trim().length === 0 || key.length > 200) {
      throw new Error('Invalid key for brute force clearing');
    }

    try {
      await this.redisClient.del(`bf:${key}`);
    } catch (error) {
      this.securityLogger.logSecurityError(
        'REDIS_BRUTE_FORCE_CLEAR_ERROR',
        `Failed to clear brute force attempts: ${(error as Error).message}`,
      );
      // В случае ошибки Redis, логируем но не блокируем
    }
  }

  // Получение времени до разблокировки
  async getBlockTimeRemaining(key: string): Promise<number> {
    // Валидация входных данных
    if (!key || key.trim().length === 0 || key.length > 200) {
      throw new Error('Invalid key for block time check');
    }

    try {
      return await this.redisClient.ttl(`bf:${key}`);
    } catch (error) {
      this.securityLogger.logSecurityError(
        'REDIS_BRUTE_FORCE_TTL_ERROR',
        `Failed to get block time remaining: ${(error as Error).message}`,
      );
      // В случае ошибки Redis, возвращаем 0 (разблокировано)
      return 0;
    }
  }
}
