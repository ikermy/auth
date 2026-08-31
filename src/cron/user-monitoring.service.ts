import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { ConfigService } from '@nestjs/config';
import { Cron } from '@nestjs/schedule';
import { EventType, Severity } from '../../generated/prisma';

interface UserCheckResult {
  telegramWithoutEmail: number;
  emailWithoutTelegram: number;
  inactiveSeedUsers: number;
  totalUsers: number;
}

@Injectable()
export class UserMonitoringService {
  private readonly logger = new Logger(UserMonitoringService.name);

  constructor(
    private readonly prismaService: PrismaService,
    private readonly configService: ConfigService,
  ) {}

  // Запускается каждый день в 9:00 UTC
  @Cron('0 9 * * *', { name: 'daily-user-check', timeZone: 'UTC' })
  async dailyUserCheck(): Promise<void> {
    this.logger.log('🔄 Starting daily user monitoring check...');

    try {
      const result = await this.performUserChecks();

      this.logger.log(`📊 Daily user check completed:`, {
        totalUsers: result.totalUsers,
        telegramWithoutEmail: result.telegramWithoutEmail,
        emailWithoutTelegram: result.emailWithoutTelegram,
        inactiveSeedUsers: result.inactiveSeedUsers,
      });

      // Здесь можно добавить отправку уведомлений или логирование в внешнюю систему
      await this.logUserCheckResults(result);

      // Бизнес-действие: фиксируем проблемы как security-события (мониторинг не
      // должен быть только логом количества пользователей — §12)
      await this.recordIssueEvents();
    } catch (error) {
      this.logger.error(
        `❌ Daily user check failed: ${(error as Error).message}`,
      );
    }
  }

  // Запускается каждые 6 часов для более частых проверок
  @Cron('0 */6 * * *', { name: 'frequent-user-check', timeZone: 'UTC' })
  async frequentUserCheck(): Promise<void> {
    this.logger.log('🔄 Starting frequent user monitoring check...');

    try {
      const result = await this.performUserChecks();

      // Логируем только если есть проблемы
      if (
        result.telegramWithoutEmail > 0 ||
        result.emailWithoutTelegram > 0 ||
        result.inactiveSeedUsers > 0
      ) {
        this.logger.warn(`⚠️ User issues detected:`, {
          telegramWithoutEmail: result.telegramWithoutEmail,
          emailWithoutTelegram: result.emailWithoutTelegram,
          inactiveSeedUsers: result.inactiveSeedUsers,
        });
      }
    } catch (error) {
      this.logger.error(
        `❌ Frequent user check failed: ${(error as Error).message}`,
      );
    }
  }

  private async performUserChecks(): Promise<UserCheckResult> {
    // Получаем общее количество пользователей
    const totalUsers = await this.prismaService.user.count();

    // a) Пользователи с привязанным Telegram, но без email
    const telegramWithoutEmail = await this.prismaService.user.count({
      where: {
        telegramId: { not: null },
        isTelegramVerified: true,
        email: {
          startsWith: 'tg_', // Безопасный email, сгенерированный системой
        },
      },
    });

    // b) Пользователи с привязанным Email, но без Telegram
    const emailWithoutTelegram = await this.prismaService.user.count({
      where: {
        email: { not: { startsWith: 'tg_' } }, // Реальный email
        isEmailVerified: true,
        OR: [{ telegramId: null }, { isTelegramVerified: false }],
      },
    });

    // c) Пользователи с неактивными Seed фразами
    const seedInactivityDays = this.configService.get<number>(
      'SEED_INACTIVITY_DAYS',
      30,
    );
    const inactiveSeedThreshold = new Date();
    inactiveSeedThreshold.setDate(
      inactiveSeedThreshold.getDate() - seedInactivityDays,
    );

    const inactiveSeedUsers = await this.prismaService.user.count({
      where: {
        seedPhraseEnabled: true,
        OR: [
          { seedPhraseLastVerifiedAt: null },
          { seedPhraseLastVerifiedAt: { lt: inactiveSeedThreshold } },
        ],
      },
    });

    return {
      telegramWithoutEmail,
      emailWithoutTelegram,
      inactiveSeedUsers,
      totalUsers,
    };
  }

  private async logUserCheckResults(result: UserCheckResult): Promise<void> {
    // Логируем результаты в базу данных или внешнюю систему
    this.logger.log('📝 Logging user check results...');

    // Здесь можно добавить:
    // - Сохранение в таблицу мониторинга
    // - Отправку уведомлений администраторам
    // - Интеграцию с внешними системами мониторинга
  }

  // Создаёт security-события для проблем, выявленных мониторингом.
  // Превращает «просто лог количества» в полезное доменное действие.
  private async recordIssueEvents(): Promise<void> {
    try {
      const issues = await this.getUsersWithIssues();

      const records: { userId: string; type: string }[] = [
        ...issues.inactiveSeedUsers.map((u: any) => ({
          userId: u.id,
          type: 'stale_recovery_phrase',
        })),
        ...issues.telegramWithoutEmail.map((u: any) => ({
          userId: u.id,
          type: 'telegram_without_email',
        })),
      ];

      for (const record of records) {
        await this.prismaService.securityEvent.create({
          data: {
            userId: record.userId,
            eventType: EventType.SUSPICIOUS_ACTIVITY,
            severity: Severity.MEDIUM,
            description: `User monitoring: ${record.type}`,
            metadata: { source: 'user_monitoring', type: record.type },
          },
        });
      }

      if (records.length > 0) {
        this.logger.log(
          `📝 Recorded ${records.length} monitoring security events`,
        );
      }
    } catch (error) {
      this.logger.error(
        `Failed to record monitoring events: ${(error as Error).message}`,
      );
    }
  }

  // Метод для ручного запуска проверки (для тестирования)
  async manualUserCheck(): Promise<UserCheckResult> {
    this.logger.log('🔧 Manual user check triggered...');
    return await this.performUserChecks();
  }

  // Получение детальной информации о пользователях с проблемами
  async getUsersWithIssues(): Promise<{
    telegramWithoutEmail: any[];
    emailWithoutTelegram: any[];
    inactiveSeedUsers: any[];
  }> {
    // a) Детали пользователей с Telegram без email
    const telegramWithoutEmail = await this.prismaService.user.findMany({
      where: {
        telegramId: { not: null },
        isTelegramVerified: true,
        email: { startsWith: 'tg_' },
      },
      select: {
        id: true,
        email: true,
        telegramId: true,
        telegramUsername: true,
        telegramFirstName: true,
        telegramLastName: true,
        createdAt: true,
      },
    });

    // b) Детали пользователей с Email без Telegram
    const emailWithoutTelegram = await this.prismaService.user.findMany({
      where: {
        email: { not: { startsWith: 'tg_' } },
        isEmailVerified: true,
        OR: [{ telegramId: null }, { isTelegramVerified: false }],
      },
      select: {
        id: true,
        email: true,
        telegramId: true,
        isTelegramVerified: true,
        createdAt: true,
      },
    });

    // c) Детали пользователей с неактивными Seed фразами
    const seedInactivityDays = this.configService.get<number>(
      'SEED_INACTIVITY_DAYS',
      30,
    );
    const inactiveSeedThreshold = new Date();
    inactiveSeedThreshold.setDate(
      inactiveSeedThreshold.getDate() - seedInactivityDays,
    );

    const inactiveSeedUsers = await this.prismaService.user.findMany({
      where: {
        seedPhraseEnabled: true,
        OR: [
          { seedPhraseLastVerifiedAt: null },
          { seedPhraseLastVerifiedAt: { lt: inactiveSeedThreshold } },
        ],
      },
      select: {
        id: true,
        email: true,
        telegramId: true,
        seedPhraseLastVerifiedAt: true,
        seedPhraseVerificationCount: true,
        createdAt: true,
      },
    });

    return {
      telegramWithoutEmail,
      emailWithoutTelegram,
      inactiveSeedUsers,
    };
  }
}
