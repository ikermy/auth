import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class OracleUsernameService {
  private readonly logger = new Logger(OracleUsernameService.name);

  /**
   * Генерирует Oracle Username на основе Telegram данных
   * @param telegramId - ID пользователя в Telegram
   * @param telegramUsername - Username пользователя в Telegram (опционально)
   * @returns Oracle Username
   */
  generateOracleUsername(
    telegramId: string,
    telegramUsername?: string,
  ): string {
    // Валидация входных данных
    if (!telegramId || telegramId.trim().length === 0) {
      throw new Error('Telegram ID is required for Oracle username generation');
    }

    // Если есть Telegram username и он не пустой, используем его
    if (telegramUsername && telegramUsername.trim().length > 0) {
      const cleanUsername = telegramUsername.trim();
      this.logger.debug(`Using Telegram username: ${cleanUsername}`);
      return cleanUsername;
    }

    // Если нет username, используем Telegram ID с префиксом
    const oracleUsername = `tg_${telegramId}`;
    this.logger.debug(
      `Using Telegram ID for Oracle username: ${oracleUsername}`,
    );
    return oracleUsername;
  }

  /**
   * Проверяет, является ли Oracle Username валидным
   * @param username - Username для проверки
   * @returns true если валидный
   */
  isValidOracleUsername(username: string): boolean {
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
   * Нормализует Oracle Username (убирает пробелы, приводит к нижнему регистру)
   * @param username - Username для нормализации
   * @returns Нормализованный username
   */
  normalizeOracleUsername(username: string): string {
    if (!username) {
      return '';
    }

    return username.trim().toLowerCase();
  }

  /**
   * Генерирует альтернативный Oracle Username с суффиксом
   * @param baseUsername - Базовый username
   * @param suffix - Суффикс для добавления
   * @returns Username с суффиксом
   */
  generateAlternativeOracleUsername(
    baseUsername: string,
    suffix: string,
  ): string {
    const normalizedBase = this.normalizeOracleUsername(baseUsername);
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
}
