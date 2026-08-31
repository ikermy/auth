import { Injectable, Logger, Optional } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { EventType, Severity } from '../../generated/prisma';
import { KafkaProducerService } from './services/kafka-producer.service';

@Injectable()
export class SecurityLoggerService {
  private readonly logger = new Logger(SecurityLoggerService.name);

  constructor(
    private readonly prismaService: PrismaService,
    @Optional() private readonly kafkaProducer?: KafkaProducerService,
  ) {}

  // Логирование подозрительной активности
  async logSuspiciousActivity(
    ip: string,
    method: string,
    url: string,
    reason: string,
  ): Promise<void> {
    // Валидация входных данных
    if (!ip || ip.trim().length === 0 || ip.length > 45) {
      throw new Error('Invalid IP address for logging');
    }

    if (!method || method.trim().length === 0 || method.length > 50) {
      throw new Error('Invalid method for logging');
    }

    if (!url || url.trim().length === 0 || url.length > 500) {
      throw new Error('Invalid URL for logging');
    }

    if (!reason || reason.trim().length === 0 || reason.length > 1000) {
      throw new Error('Invalid reason for logging');
    }

    this.logger.warn(
      `🚨 [SECURITY] SUSPICIOUS_ACTIVITY detected from IP: ${ip} | Method: ${method} | URL: ${url} | Reason: ${reason}`,
    );
    await this.prismaService.securityEvent.create({
      data: {
        ipAddress: ip,
        eventType: EventType.SUSPICIOUS_ACTIVITY,
        description: reason,
        severity: Severity.MEDIUM,
        userId: null,
      },
    });
  }

  // Логирование успешных запросов
  async logSuccess(ip: string, method: string, url: string): Promise<void> {
    this.logger.log(
      `✅ [SECURITY] SUCCESS request from IP: ${ip} | Method: ${method} | URL: ${url}`,
    );
    await this.prismaService.securityEvent.create({
      data: {
        ipAddress: ip,
        eventType: EventType.SUCCESS,
        description: 'Successful request',
        severity: Severity.LOW,
        userId: null,
      },
    });
  }

  // Логирование ошибок
  async logError(
    ip: string,
    method: string,
    url: string,
    error: string,
  ): Promise<void> {
    this.logger.error(
      `❌ [SECURITY] ERROR request from IP: ${ip} | Method: ${method} | Error: ${error}`,
    );
    await this.prismaService.securityEvent.create({
      data: {
        ipAddress: ip,
        eventType: EventType.ERROR,
        description: error,
        severity: Severity.MEDIUM,
        userId: null,
      },
    });
  }

  // Логирование превышения лимитов
  async logRateLimitExceeded(ip: string): Promise<void> {
    this.logger.warn(`⚠️ [SECURITY] RATE_LIMIT_EXCEEDED for IP: ${ip}`);
    await this.prismaService.securityEvent.create({
      data: {
        ipAddress: ip,
        eventType: EventType.RATE_LIMIT_EXCEEDED,
        description: 'Rate limit exceeded',
        severity: Severity.MEDIUM,
        userId: null,
      },
    });
  }

  // Логирование блокировки IP
  logIpBlocked(ip: string, reason: string): void {
    this.logger.warn(
      `🚫 [SECURITY] IP_BLOCKED | IP: ${ip} | Reason: ${reason}`,
    );
  }

  // Логирование добавления в черный список
  logIpBlacklisted(ip: string): void {
    this.logger.warn(`🚫 [SECURITY] IP_BLACKLISTED | IP: ${ip}`);
  }

  // Логирование удаления из черного списка
  logIpWhitelisted(ip: string): void {
    this.logger.log(`✅ [SECURITY] IP_WHITELISTED | IP: ${ip}`);
  }

  // Логирование ошибок безопасности
  logSecurityError(error: string, details?: string): void {
    this.logger.error(
      `💥 [SECURITY] SECURITY_ERROR | Error: ${error}` +
        (details ? ` | Details: ${details}` : ''),
    );
  }

  // Логирование аутентификации
  async logAuthAttempt(
    ip: string,
    email: string,
    success: boolean,
  ): Promise<void> {
    // Валидация входных данных
    if (!ip || ip.trim().length === 0 || ip.length > 45) {
      throw new Error('Invalid IP address for auth logging');
    }

    if (!email || email.trim().length === 0 || email.length > 255) {
      throw new Error('Invalid email for auth logging');
    }

    const icon = success ? '🔐' : '🔓';
    const status = success ? 'SUCCESS' : 'FAILED';

    this.logger.log(
      `${icon} [AUTH] ${status} login attempt from IP: ${ip} for email: ${email}`,
    );

    // Записываем в БД для аудита
    try {
      const user = await this.prismaService.user.findUnique({
        where: { email },
      });
      if (user) {
        await this.prismaService.securityEvent.create({
          data: {
            userId: user.id,
            eventType: EventType.AUTH_ATTEMPT,
            severity: success ? Severity.LOW : Severity.MEDIUM,
            description: `${status} login attempt from IP: ${ip}`,
            ipAddress: ip,
            metadata: { success, email },
          },
        });

        // Уведомление о значимом событии (§9.12)
        await this.kafkaProducer?.publish({
          type: 'AUTH_ATTEMPT',
          userId: user.id,
          success,
          email,
          ip,
          timestamp: new Date().toISOString(),
        });
      }
    } catch (error) {
      this.logger.error(
        `Failed to log auth attempt to DB: ${(error as Error).message}`,
      );
    }
  }

  // Логирование регистрации
  async logRegistration(
    ip: string,
    email: string,
    success: boolean,
  ): Promise<void> {
    const icon = success ? '📝' : '❌';
    const status = success ? 'SUCCESS' : 'FAILED';

    this.logger.log(
      `${icon} [AUTH] ${status} registration from IP: ${ip} for email: ${email}`,
    );

    // Записываем в БД для аудита
    try {
      const user = await this.prismaService.user.findUnique({
        where: { email },
      });
      if (user) {
        await this.prismaService.securityEvent.create({
          data: {
            userId: user.id,
            eventType: EventType.REGISTRATION,
            severity: success ? Severity.LOW : Severity.MEDIUM,
            description: `${status} registration from IP: ${ip}`,
            ipAddress: ip,
            metadata: { success, email },
          },
        });

        // Уведомление о значимом событии (§9.12)
        await this.kafkaProducer?.publish({
          type: 'REGISTRATION',
          userId: user.id,
          success,
          email,
          ip,
          timestamp: new Date().toISOString(),
        });
      }
    } catch (error) {
      this.logger.error(
        `Failed to log registration to DB: ${(error as Error).message}`,
      );
    }
  }

  // Логирование обновления токенов
  async logTokenRefresh(ip: string, success: boolean): Promise<void> {
    const icon = success ? '🔄' : '❌';
    const status = success ? 'SUCCESS' : 'FAILED';

    this.logger.log(`${icon} [AUTH] ${status} token refresh from IP: ${ip}`);

    // Записываем в БД для аудита (без привязки к пользователю)
    try {
      await this.prismaService.securityEvent.create({
        data: {
          userId: null, // Для системных событий
          eventType: EventType.TOKEN_REFRESH,
          severity: success ? Severity.LOW : Severity.MEDIUM,
          description: `${status} token refresh from IP: ${ip}`,
          ipAddress: ip,
          metadata: { success },
        },
      });
    } catch (error) {
      this.logger.error(
        `Failed to log token refresh to DB: ${(error as Error).message}`,
      );
    }
  }

  // Логирование JWT событий
  logJwtEvent(event: string, details: string): void {
    // Валидация входных данных
    if (!event || event.trim().length === 0 || event.length > 100) {
      throw new Error('Invalid JWT event for logging');
    }

    if (!details || details.trim().length === 0 || details.length > 1000) {
      throw new Error('Invalid JWT details for logging');
    }

    this.logger.log(`🔑 [JWT] ${event.toUpperCase()} | ${details}`);
  }

  // Логирование Redis событий
  logRedisEvent(event: string, details: string): void {
    // Валидация входных данных
    if (!event || event.trim().length === 0 || event.length > 100) {
      throw new Error('Invalid Redis event for logging');
    }

    if (!details || details.trim().length === 0 || details.length > 1000) {
      throw new Error('Invalid Redis details for logging');
    }

    this.logger.log(`🗄️ [REDIS] ${event.toUpperCase()} | ${details}`);
  }

  // Логирование аномалий
  logAnomaly(
    protocol: string,
    email: string,
    anomalyScore: { score: number },
  ): void {
    // Валидация входных данных
    if (!protocol || protocol.trim().length === 0 || protocol.length > 50) {
      throw new Error('Invalid protocol for anomaly logging');
    }

    if (!email || email.trim().length === 0 || email.length > 255) {
      throw new Error('Invalid email for anomaly logging');
    }

    if (
      !anomalyScore ||
      typeof anomalyScore.score !== 'number' ||
      anomalyScore.score < 0 ||
      anomalyScore.score > 1
    ) {
      throw new Error('Invalid anomaly score for logging');
    }

    const severity =
      anomalyScore.score > 0.8
        ? Severity.CRITICAL
        : anomalyScore.score > 0.6
          ? Severity.HIGH
          : Severity.MEDIUM;

    this.logger.log(
      `🚨 [ANOMALY_DETECTED] ${severity} score: ${anomalyScore.score.toFixed(2)} for ${email} via ${protocol}`,
    );
  }
}
