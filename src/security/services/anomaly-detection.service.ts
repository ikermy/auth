import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../prisma.service';
import { SecurityLoggerService } from '../security-logger.service';
import { createClient, RedisClientType } from 'redis';

interface UserBehavior {
  userId: string;
  ipAddress: string;
  userAgent: string;
  action: string;
  timestamp: Date;
  success: boolean;
}

interface AnomalyScore {
  score: number;
  factors: string[];
  threshold: number;
}

@Injectable()
export class AnomalyDetectionService {
  private redisClient!: RedisClientType;
  private readonly anomalyThreshold: number;

  constructor(
    private readonly configService: ConfigService,
    private readonly prismaService: PrismaService,
    private readonly securityLogger: SecurityLoggerService,
  ) {
    this.anomalyThreshold = this.configService.get('ANOMALY_THRESHOLD', 0.7);
  }

  async onModuleInit() {
    try {
      await this.initRedis();
    } catch (error) {
      this.securityLogger.logSecurityError(
        'ANOMALY_DETECTION_INIT_ERROR',
        `Failed to initialize AnomalyDetectionService: ${(error as Error).message}`,
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
          'AnomalyDetectionService connected to Redis',
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
        `Failed to configure Redis for AnomalyDetectionService: ${(error as Error).message}`,
      );
      throw error;
    }
  }

  // Анализ поведения пользователя
  async analyzeUserBehavior(
    userId: string,
    behavior: UserBehavior,
  ): Promise<AnomalyScore> {
    // Валидация входных данных
    if (!userId || userId.trim().length === 0 || userId.length > 100) {
      throw new Error('Invalid user ID');
    }

    if (!behavior || typeof behavior !== 'object') {
      throw new Error('Invalid behavior data');
    }

    if (
      !behavior.ipAddress ||
      behavior.ipAddress.trim().length === 0 ||
      behavior.ipAddress.length > 45
    ) {
      throw new Error('Invalid IP address');
    }

    if (
      !behavior.userAgent ||
      behavior.userAgent.trim().length === 0 ||
      behavior.userAgent.length > 500
    ) {
      throw new Error('Invalid user agent');
    }

    const factors: string[] = [];
    let score = 0;

    // 1. Анализ IP адреса
    const ipScore = await this.analyzeIPAddress(userId, behavior.ipAddress);
    score += ipScore.score;
    if (ipScore.factors.length > 0) {
      factors.push(...ipScore.factors);
    }

    // 2. Анализ User-Agent
    const uaScore = await this.analyzeUserAgent(userId, behavior.userAgent);
    score += uaScore.score;
    if (uaScore.factors.length > 0) {
      factors.push(...uaScore.factors);
    }

    // 3. Анализ времени активности
    const timeScore = await this.analyzeTimePattern(userId, behavior.timestamp);
    score += timeScore.score;
    if (timeScore.factors.length > 0) {
      factors.push(...timeScore.factors);
    }

    // 4. Анализ частоты действий
    const frequencyScore = await this.analyzeActionFrequency(
      userId,
      behavior.action,
    );
    score += frequencyScore.score;
    if (frequencyScore.factors.length > 0) {
      factors.push(...frequencyScore.factors);
    }

    // 5. Анализ успешности действий
    const successScore = await this.analyzeSuccessRate(
      userId,
      behavior.success,
    );
    score += successScore.score;
    if (successScore.factors.length > 0) {
      factors.push(...successScore.factors);
    }

    // Нормализуем score до 0-1
    const normalizedScore = Math.min(score / 5, 1);

    const result: AnomalyScore = {
      score: normalizedScore,
      factors,
      threshold: this.anomalyThreshold,
    };

    // Логируем аномалию если превышен порог
    if (normalizedScore > this.anomalyThreshold) {
      this.securityLogger.logSecurityError(
        'ANOMALY_DETECTED',
        `User: ${userId}, Score: ${normalizedScore.toFixed(2)}, Factors: ${factors.join(', ')}`,
      );
    }

    return result;
  }

  // Анализ IP адреса
  private async analyzeIPAddress(
    userId: string,
    ipAddress: string,
  ): Promise<{ score: number; factors: string[] }> {
    // Валидация входных данных
    if (!userId || userId.trim().length === 0 || userId.length > 100) {
      throw new Error('Invalid user ID for IP analysis');
    }

    if (!ipAddress || ipAddress.trim().length === 0 || ipAddress.length > 45) {
      throw new Error('Invalid IP address for analysis');
    }

    const factors: string[] = [];
    let score = 0;

    try {
      // Получаем историю IP адресов пользователя
      const userIPs = await this.prismaService.loginAttempt.findMany({
        where: { userId },
        select: { ipAddress: true },
        distinct: ['ipAddress'],
        orderBy: { timestamp: 'desc' },
        take: 10,
      });

      const knownIPs = userIPs.map((attempt) => attempt.ipAddress);

      // Новый IP адрес
      if (!knownIPs.includes(ipAddress)) {
        score += 0.3;
        factors.push('new_ip_address');
      }

      // Проверяем геолокацию (можно интегрировать с внешним API)
      const isSuspiciousLocation = this.checkSuspiciousLocation(ipAddress);
      if (isSuspiciousLocation) {
        score += 0.4;
        factors.push('suspicious_location');
      }
    } catch (error) {
      this.securityLogger.logSecurityError(
        'IP_ANALYSIS_ERROR',
        `Failed to analyze IP address for user ${userId}: ${(error as Error).message}`,
      );
      // В случае ошибки БД, не увеличиваем score
    }

    return { score, factors };
  }

  // Анализ User-Agent
  private async analyzeUserAgent(
    userId: string,
    userAgent: string,
  ): Promise<{ score: number; factors: string[] }> {
    // Валидация входных данных
    if (!userId || userId.trim().length === 0 || userId.length > 100) {
      throw new Error('Invalid user ID for User-Agent analysis');
    }

    if (!userAgent || userAgent.trim().length === 0 || userAgent.length > 500) {
      throw new Error('Invalid User-Agent for analysis');
    }

    const factors: string[] = [];
    let score = 0;

    try {
      // Получаем историю User-Agent пользователя
      const userUAs = await this.prismaService.loginAttempt.findMany({
        where: { userId },
        select: { userAgent: true },
        distinct: ['userAgent'],
        orderBy: { timestamp: 'desc' },
        take: 5,
      });

      const knownUAs = userUAs.map((attempt) => attempt.userAgent);

      // Новый User-Agent
      if (!knownUAs.includes(userAgent)) {
        score += 0.2;
        factors.push('new_user_agent');
      }

      // Подозрительные User-Agent
      const suspiciousPatterns = [
        /bot/i,
        /crawler/i,
        /spider/i,
        /scraper/i,
        /curl/i,
        /wget/i,
      ];

      if (suspiciousPatterns.some((pattern) => pattern.test(userAgent))) {
        score += 0.5;
        factors.push('suspicious_user_agent');
      }
    } catch (error) {
      this.securityLogger.logSecurityError(
        'USER_AGENT_ANALYSIS_ERROR',
        `Failed to analyze User-Agent for user ${userId}: ${(error as Error).message}`,
      );
      // В случае ошибки БД, не увеличиваем score
    }

    return { score, factors };
  }

  // Анализ временных паттернов
  private async analyzeTimePattern(
    userId: string,
    timestamp: Date,
  ): Promise<{ score: number; factors: string[] }> {
    const factors: string[] = [];
    let score = 0;

    const hour = timestamp.getHours();

    // Активность в необычное время (2-6 утра)
    if (hour >= 2 && hour <= 6) {
      score += 0.3;
      factors.push('unusual_time');
    }

    // Получаем историю активности пользователя
    const recentActivity = await this.prismaService.loginAttempt.findMany({
      where: { userId },
      orderBy: { timestamp: 'desc' },
      take: 10,
    });

    // Слишком частые попытки
    if (recentActivity && recentActivity.length >= 5) {
      const timeSpan =
        recentActivity[0].timestamp.getTime() -
        recentActivity[4].timestamp.getTime();
      const minutesSpan = timeSpan / (1000 * 60);

      if (minutesSpan < 5) {
        // 5 попыток за 5 минут
        score += 0.4;
        factors.push('high_frequency');
      }
    }

    return { score, factors };
  }

  // Анализ частоты действий
  private async analyzeActionFrequency(
    userId: string,
    action: string,
  ): Promise<{ score: number; factors: string[] }> {
    const factors: string[] = [];
    let score = 0;

    try {
      const key = `action_freq:${userId}:${action}`;
      const count = await this.redisClient.incr(key);
      await this.redisClient.expire(key, 3600); // 1 час

      // Слишком много действий за короткое время
      if (count > 50) {
        score += 0.3;
        factors.push('excessive_actions');
      }
    } catch (error) {
      this.securityLogger.logSecurityError(
        'REDIS_ACTION_FREQUENCY_ERROR',
        `Failed to analyze action frequency: ${(error as Error).message}`,
      );
      // В случае ошибки Redis, не увеличиваем score
    }

    return { score, factors };
  }

  // Анализ успешности действий
  private async analyzeSuccessRate(
    userId: string,
    success: boolean,
  ): Promise<{ score: number; factors: string[] }> {
    const factors: string[] = [];
    let score = 0;

    try {
      const key = `success_rate:${userId}`;
      const totalKey = `${key}:total`;
      const successKey = `${key}:success`;

      await this.redisClient.incr(totalKey);
      if (success) {
        await this.redisClient.incr(successKey);
      }

      await this.redisClient.expire(totalKey, 3600);
      await this.redisClient.expire(successKey, 3600);

      const total = await this.redisClient.get(totalKey);
      const successCount = await this.redisClient.get(successKey);

      if (total && successCount) {
        const totalNum = parseInt(total as string);
        const successNum = parseInt(successCount as string);

        // Проверка на валидность чисел
        if (isNaN(totalNum) || isNaN(successNum) || totalNum <= 0) {
          return { score: 0, factors: [] };
        }

        const successRate = successNum / totalNum;

        // Низкий процент успешности
        if (successRate < 0.3) {
          score += 0.4;
          factors.push('low_success_rate');
        }
      }
    } catch (error) {
      this.securityLogger.logSecurityError(
        'REDIS_SUCCESS_RATE_ERROR',
        `Failed to analyze success rate: ${(error as Error).message}`,
      );
      // В случае ошибки Redis, не увеличиваем score
    }

    return { score, factors };
  }

  // Проверка подозрительной локации (улучшенная)
  private checkSuspiciousLocation(ipAddress: string): boolean {
    // Здесь можно интегрировать с сервисами геолокации
    // Например: MaxMind, IP2Location, etc.
    const suspiciousRanges = [
      '192.168.1.0/24', // Локальная сеть
      '10.0.0.0/8', // Приватная сеть
      '172.16.0.0/12', // Приватная сеть
      '127.0.0.0/8', // Loopback
    ];

    // Улучшенная проверка CIDR блоков
    return suspiciousRanges.some((range) => {
      return this.isIpInRange(ipAddress, range);
    });
  }

  // Проверка IP адреса в CIDR диапазоне
  private isIpInRange(ip: string, cidr: string): boolean {
    try {
      const [network, bitsStr] = cidr.split('/');
      const bits = parseInt(bitsStr, 10);

      // Проверка на валидность bits
      if (isNaN(bits) || bits < 0 || bits > 32) {
        throw new Error('Invalid CIDR bits');
      }

      const mask = ~((1 << (32 - bits)) - 1);

      const ipNum = this.ipToNumber(ip);
      const networkNum = this.ipToNumber(network);

      return (ipNum & mask) === (networkNum & mask);
    } catch (error) {
      this.securityLogger.logSecurityError(
        'IP_RANGE_CHECK_ERROR',
        `Failed to check IP range: ${ip} in ${cidr}`,
      );
      return false;
    }
  }

  // Конвертация IP адреса в число
  private ipToNumber(ip: string): number {
    const parts = ip.split('.');
    if (parts.length !== 4) {
      throw new Error('Invalid IP address format');
    }

    return (
      parts.reduce((acc, part) => {
        const num = parseInt(part, 10);
        if (isNaN(num) || num < 0 || num > 255) {
          throw new Error('Invalid IP address part');
        }
        return (acc << 8) + num;
      }, 0) >>> 0
    ); // Преобразуем в unsigned 32-bit
  }

  // Получение статистики аномалий
  async getAnomalyStats(userId: string): Promise<{
    totalEvents: number;
    anomalyEvents: number;
    averageScore: number;
    lastAnomaly: Date | null;
  }> {
    // Валидация входных данных
    if (!userId || userId.trim().length === 0 || userId.length > 100) {
      throw new Error('Invalid user ID for anomaly stats');
    }

    try {
      // const events = await this.prismaService.loginAttempts.findMany({
      const events = await this.prismaService.loginAttempt.findMany({
        where: { userId },
        orderBy: { timestamp: 'desc' },
        take: 100,
      });

      const totalEvents = events.length;
      const anomalyEvents = events.filter((e) =>
        e.failureReason?.includes('anomaly'),
      ).length;
      const averageScore = totalEvents > 0 ? anomalyEvents / totalEvents : 0;
      const lastAnomaly =
        events.find((e) => e.failureReason?.includes('anomaly'))?.timestamp ||
        null;

      return {
        totalEvents,
        anomalyEvents,
        averageScore,
        lastAnomaly,
      };
    } catch (error) {
      this.securityLogger.logSecurityError(
        'ANOMALY_STATS_ERROR',
        `Failed to get anomaly stats for user ${userId}: ${(error as Error).message}`,
      );
      throw error;
    }
  }
}
