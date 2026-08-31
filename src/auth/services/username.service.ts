import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../prisma.service';

@Injectable()
export class UsernameService {
  private readonly logger = new Logger(UsernameService.name);

  constructor(
    private readonly prismaService: PrismaService,
    private readonly configService: ConfigService,
  ) {}

  /**
   * Генерирует User Username на основе Telegram данных
   * @param telegramId - ID пользователя в Telegram
   * @param telegramUsername - Username пользователя в Telegram (опционально)
   * @returns User Username
   */
  generateUsername(
    telegramId: string,
    telegramUsername?: string,
  ): string {
    // Валидация входных данных
    if (!telegramId || telegramId.trim().length === 0) {
      throw new Error('Telegram ID is required for User username generation');
    }

    // Если есть Telegram username и он не пустой, используем его
    if (telegramUsername && telegramUsername.trim().length > 0) {
      const cleanUsername = telegramUsername.trim();
      this.logger.debug(`Using Telegram username: ${cleanUsername}`);
      return cleanUsername;
    }

    // Если нет username, используем Telegram ID с префиксом
    const username = `tg_${telegramId}`;
    this.logger.debug(
      `Using Telegram ID for User username: ${username}`,
    );
    return username;
  }

  /**
   * Проверяет, является ли User Username валидным
   * @param username - Username для проверки
   * @returns true если валидный
   */
  isValidUserUsername(username: string): boolean {
    if (!username || username.trim().length === 0) {
      return false;
    }

    const cleanUsername = username.trim();

    // Проверяем длину (минимум 1, максимум 50 символов)
    if (cleanUsername.length < 1 || cleanUsername.length > 50) {
      return false;
    }

    // Проверяем, что username содержит только допустимые символы
    // Разрешаем буквы, цифры, подчеркивания, дефисы
    const validPattern = /^[a-zA-Z0-9_-]+$/;
    return validPattern.test(cleanUsername);
  }

  /**
   * Нормализует User Username (убирает пробелы, приводит к нижнему регистру)
   * @param username - Username для нормализации
   * @returns Нормализованный username
   */
  normalizeUserUsername(username: string): string {
    if (!username) {
      return '';
    }

    return username.trim().toLowerCase();
  }

  /**
   * Генерирует альтернативный User Username с суффиксом
   * @param baseUsername - Базовый username
   * @param suffix - Суффикс для добавления
   * @returns Username с суффиксом
   */
  generateAlternativeUsername(
    baseUsername: string,
    suffix: string,
  ): string {
    const normalizedBase = this.normalizeUserUsername(baseUsername);
    const normalizedSuffix = suffix.trim();

    // Проверяем, что итоговая длина не превышает лимит
    const maxLength = 50;
    const separator = '_';

    if (
      normalizedBase.length + separator.length + normalizedSuffix.length >
      maxLength
    ) {
      // Обрезаем базовый username если нужно
      const availableLength =
        maxLength - separator.length - normalizedSuffix.length;
      const truncatedBase = normalizedBase.substring(
        0,
        Math.max(1, availableLength),
      );
      return `${truncatedBase}${separator}${normalizedSuffix}`;
    }

    return `${normalizedBase}${separator}${normalizedSuffix}`;
  }

  /**
   * Резервирует освободившийся User username за прежним User ID на grace period (§2.3).
   */
  async reserveUsername(userId: string, username: string): Promise<void> {
    if (!username || username.trim().length === 0) {
      return;
    }

    const graceDays = this.configService.get<number>(
      'USERNAME_GRACE_PERIOD_DAYS',
      30,
    );
    const expiresAt = new Date(Date.now() + graceDays * 24 * 60 * 60 * 1000);

    const existing = await this.prismaService.usernameReservation.findUnique({
      where: { username },
    });

    if (existing) {
      if (existing.userId === userId && existing.state === 'active') {
        await this.prismaService.usernameReservation.update({
          where: { username },
          data: { expiresAt },
        });
      }
      return;
    }

    await this.prismaService.usernameReservation.create({
      data: { userId, username, expiresAt },
    });
    this.logger.debug(
      `Reserved User username "${username}" for user ${userId} until ${expiresAt.toISOString()}`,
    );
  }

  /**
   * Проверяет, зарезервировано ли имя за ДРУГИМ User ID в активном grace period.
   */
  async isUsernameReservedByOther(
    username: string,
    userId: string,
  ): Promise<boolean> {
    const reservation = await this.prismaService.usernameReservation.findUnique(
      { where: { username } },
    );
    return (
      !!reservation &&
      reservation.userId !== userId &&
      reservation.state === 'active' &&
      reservation.expiresAt > new Date()
    );
  }
}
