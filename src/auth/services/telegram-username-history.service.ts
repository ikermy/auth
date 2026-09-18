import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../prisma.service';
import { Prisma } from '../../../generated/prisma';

export type TelegramUsernameEventType = 'set' | 'changed' | 'removed' | 'migrated';
export type TelegramUsernameSource = 'telegram_widget' | 'manual' | 'audit_migration';

export interface TelegramUsernameHistoryItem {
  id: string;
  telegramUsername: string | null;
  previousUsername: string | null;
  eventType: string;
  source: string | null;
  changedAt: Date;
}

export interface TelegramUsernameHistoryPage {
  entries: TelegramUsernameHistoryItem[];
  total: number;
  page: number;
  limit: number;
}

/**
 * Хранит и отдаёт историю изменений Linked Telegram Username (users.telegramUsername).
 * Пишет запись при каждом set/changed/removed; чтение — per-user (для Settings).
 */
@Injectable()
export class TelegramUsernameHistoryService {
  private readonly logger = new Logger(TelegramUsernameHistoryService.name);

  constructor(private readonly prismaService: PrismaService) {}

  /**
   * Записать событие истории. По умолчанию — через PrismaService; внутри транзакции
   * передавать tx-клиент (см. recordIfChanged).
   */
  async record(
    userId: string,
    telegramUsername: string | null,
    previousUsername: string | null,
    eventType: TelegramUsernameEventType,
    source: TelegramUsernameSource = 'telegram_widget',
    client: Prisma.TransactionClient | PrismaService = this.prismaService,
  ): Promise<void> {
    try {
      await client.telegramUsernameHistory.create({
        data: {
          userId,
          telegramUsername: telegramUsername || null,
          previousUsername: previousUsername || null,
          eventType,
          source,
        },
      });
    } catch (error) {
      // История не должна ломать основной флоу привязки/логина.
      this.logger.error(
        `Failed to record telegram username history for user ${userId}: ${(error as Error).message}`,
      );
    }
  }

  /**
   * Записать событие только если значение реально изменилось.
   * eventType: set (было пусто → есть), changed (есть → другое есть), removed (есть → пусто).
   */
  async recordIfChanged(
    userId: string,
    previousUsername: string | null | undefined,
    nextUsername: string | null | undefined,
    source: TelegramUsernameSource = 'telegram_widget',
    client: Prisma.TransactionClient | PrismaService = this.prismaService,
  ): Promise<void> {
    const previous = (previousUsername || '').trim() || null;
    const next = (nextUsername || '').trim() || null;
    if (previous === next) return;

    let eventType: TelegramUsernameEventType;
    if (!next) {
      eventType = 'removed';
    } else if (!previous) {
      eventType = 'set';
    } else {
      eventType = 'changed';
    }

    await this.record(userId, next, previous, eventType, source, client);
  }

  /**
   * История изменений Telegram username пользователя (от свежих к старым).
   */
  async listForUser(
    userId: string,
    page = 1,
    limit = 20,
  ): Promise<TelegramUsernameHistoryPage> {
    const safePage = Math.max(1, Math.floor(page) || 1);
    const safeLimit = Math.min(100, Math.max(1, Math.floor(limit) || 20));
    const skip = (safePage - 1) * safeLimit;

    const [entries, total] = await Promise.all([
      this.prismaService.telegramUsernameHistory.findMany({
        where: { userId },
        orderBy: { changedAt: 'desc' },
        skip,
        take: safeLimit,
        select: {
          id: true,
          telegramUsername: true,
          previousUsername: true,
          eventType: true,
          source: true,
          changedAt: true,
        },
      }),
      this.prismaService.telegramUsernameHistory.count({ where: { userId } }),
    ]);

    return { entries, total, page: safePage, limit: safeLimit };
  }
}
