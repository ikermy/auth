import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../prisma.service';
import { RpcException } from '@nestjs/microservices';
import { status } from '@grpc/grpc-js';

export interface UserIdentity {
  userId: string; // ID (неизменяемый)
  username?: string; // Username (изменяемый, уникальный)
  nickname?: string; // NickName (изменяемый, неуникальный)
}

@Injectable()
export class UserIdentityService {
  private readonly logger = new Logger(UserIdentityService.name);

  constructor(private readonly prismaService: PrismaService) {}

  /**
   * Получает User идентификаторы пользователя
   */
  async getUserIdentity(userId: string): Promise<UserIdentity> {
    const user = await this.withRpcError(
      () =>
        this.prismaService.user.findUnique({
          where: { id: userId },
          select: {
            id: true,
            username: true,
            nickname: true,
          },
        }),
      'Failed to get User identity',
    );

    if (!user) {
      throw new RpcException({
        code: status.NOT_FOUND,
        message: 'User not found',
      });
    }

    return {
      userId: user.id,
      username: user.username || undefined,
      nickname: user.nickname || undefined,
    };
  }

  /**
   * Username immutable: смена запрещена для любых аккаунтов.
   */
  changeUsername(_userId: string, _newUsername: string): Promise<string> {
    void _userId;
    void _newUsername;
    throw new RpcException({
      code: status.FAILED_PRECONDITION,
      message: 'Username cannot be changed',
    });
  }

  /**
   * Возвращает полный профиль пользователя (email, username, nickname, фото, telegram, origin).
   */
  async getUserProfile(userId: string): Promise<{
    userId: string;
    email: string;
    username: string;
    nickname: string;
    photoBase64: string;
    telegramUsername: string;
    telegramId: string;
    telegramPhotoUrl: string;
    origin: string;
    isTelegramVerified: boolean;
  }> {
    if (!userId || userId.trim().length === 0 || userId.length > 100) {
      throw new RpcException({
        code: status.INVALID_ARGUMENT,
        message: 'Invalid user ID',
      });
    }

    const user = await this.prismaService.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        username: true,
        nickname: true,
        photoBase64: true,
        telegramUsername: true,
        telegramId: true,
        telegramPhotoUrl: true,
        origin: true,
        isTelegramVerified: true,
      },
    });

    if (!user) {
      throw new RpcException({
        code: status.NOT_FOUND,
        message: 'User not found',
      });
    }

    return {
      userId: user.id,
      email: user.email || '',
      username: user.username || '',
      nickname: user.nickname || '',
      photoBase64: user.photoBase64 || '',
      telegramUsername: user.telegramUsername || '',
      telegramId: user.telegramId || '',
      telegramPhotoUrl: user.telegramPhotoUrl || '',
      origin: user.origin,
      isTelegramVerified: user.isTelegramVerified,
    };
  }

  /**
   * Изменяет User NickName
   */
  async changeNickname(userId: string, newNickName: string): Promise<string> {
    // Валидация входных данных
    if (!userId || userId.trim().length === 0 || userId.length > 100) {
      throw new RpcException({
        code: status.INVALID_ARGUMENT,
        message: 'Invalid user ID',
      });
    }

    if (
      !newNickName ||
      newNickName.trim().length === 0 ||
      newNickName.length > 100
    ) {
      throw new RpcException({
        code: status.INVALID_ARGUMENT,
        message: 'Invalid nickname',
      });
    }

    // Валидация формата nickname
    const nicknameValidation = this.validateUserNickName(newNickName);
    if (!nicknameValidation.valid) {
      throw new RpcException({
        code: status.INVALID_ARGUMENT,
        message: `Nickname validation failed: ${nicknameValidation.errors.join(', ')}`,
      });
    }

    // Проверяем, что пользователь существует
    const user = await this.withRpcError(
      () => this.prismaService.user.findUnique({ where: { id: userId } }),
      'Failed to change User nickname',
    );

    if (!user) {
      throw new RpcException({
        code: status.NOT_FOUND,
        message: 'User not found',
      });
    }

    // Nickname — отдельное отображаемое имя, изменяемое для любого типа аккаунта
    // (в т.ч. telegram-origin): Telegram синхронизирует telegram*/username,
    // но не перезаписывает nickname, поэтому редактирование безопасно.

    // Обновляем User nickname (nickname не уникален, поэтому проверка на существование не нужна)
    await this.withRpcError(
      () =>
        this.prismaService.user.update({
          where: { id: userId },
          data: {
            nickname: newNickName,
          },
        }),
      'Failed to change User nickname',
    );

    this.logger.log(
      `✅ [USER] NickName changed for user ${userId}: ${user.nickname} -> ${newNickName}`,
    );
    return newNickName;
  }

  /**
   * Обновляет фотографию профиля (base64 data URL). Пустая строка удаляет фото.
   */
  async changeAvatar(userId: string, photoBase64: string): Promise<string> {
    if (!userId || userId.trim().length === 0 || userId.length > 100) {
      throw new RpcException({
        code: status.INVALID_ARGUMENT,
        message: 'Invalid user ID',
      });
    }

    const user = await this.withRpcError(
      () => this.prismaService.user.findUnique({ where: { id: userId } }),
      'Failed to change User avatar',
    );

    if (!user) {
      throw new RpcException({
        code: status.NOT_FOUND,
        message: 'User not found',
      });
    }

    // Валидация формата base64 data URL (если передано фото)
    if (photoBase64 && photoBase64.trim().length > 0) {
      const dataUrlPattern =
        /^data:image\/(png|jpeg|jpg|webp|gif);base64,[A-Za-z0-9+/=]+$/;
      if (!dataUrlPattern.test(photoBase64)) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid photo format (expected base64 data URL)',
        });
      }
      // Ограничение размера ~1MB base64 (≈750KB бинарных)
      if (photoBase64.length > 1_500_000) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Photo is too large (max ~1MB base64)',
        });
      }
    }

    await this.withRpcError(
      () =>
        this.prismaService.user.update({
          where: { id: userId },
          data: {
            photoBase64:
              photoBase64 && photoBase64.trim().length > 0 ? photoBase64 : null,
          },
        }),
      'Failed to change User avatar',
    );

    this.logger.log(`✅ [USER] Avatar changed for user ${userId}`);
    return photoBase64 || '';
  }

  /**
   * Валидирует User Username
   */
  private validateUserUsername(username: string): {
    valid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];
    const cleanUsername = username.trim();

    // Проверка длины
    if (cleanUsername.length < 3) {
      errors.push('Username must be at least 3 characters long');
    }
    if (cleanUsername.length > 50) {
      errors.push('Username must be no more than 50 characters long');
    }

    // Проверка формата (только буквы, цифры, подчеркивания, дефисы)
    const usernameRegex = /^[a-zA-Z0-9_-]+$/;
    if (!usernameRegex.test(cleanUsername)) {
      errors.push(
        'Username can only contain letters, numbers, underscores, and hyphens',
      );
    }

    // Проверка, что не начинается с цифры
    if (/^[0-9]/.test(cleanUsername)) {
      errors.push('Username cannot start with a number');
    }

    // Проверка на запрещенные слова
    const forbiddenWords = [
      'admin',
      'root',
      'system',
      'user',
      'user',
      'test',
      'null',
      'undefined',
    ];
    if (forbiddenWords.includes(cleanUsername.toLowerCase())) {
      errors.push('Username contains forbidden word');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Валидирует User NickName
   */
  private validateUserNickName(nickName: string): {
    valid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];
    const cleanNickName = nickName.trim();

    // Проверка длины
    if (cleanNickName.length < 1) {
      errors.push('Nickname must be at least 1 character long');
    }
    if (cleanNickName.length > 100) {
      errors.push('Nickname must be no more than 100 characters long');
    }

    // Проверка на запрещенные символы (более мягкая валидация для nickname)
    const nicknameRegex = /^[a-zA-Z0-9\s_-]+$/;
    if (!nicknameRegex.test(cleanNickName)) {
      errors.push(
        'Nickname can only contain letters, numbers, spaces, underscores, and hyphens',
      );
    }

    // Проверка на пустые строки
    if (cleanNickName.length === 0) {
      errors.push('Nickname cannot be empty');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Username immutable: смена запрещена всегда, независимо от типа аккаунта.
   */
  canChangeUsername(
    _userId: string,
  ): Promise<{ canChange: boolean; reason?: string }> {
    void _userId;
    return Promise.resolve({
      canChange: false,
      reason: 'Username cannot be changed',
    });
  }

  /**
   * Генерирует альтернативные username при конфликте
   */
  async generateUsernameAlternatives(
    baseUsername: string,
    userId: string,
    maxAlternatives: number = 5,
  ): Promise<string[]> {
    try {
      const alternatives: string[] = [];
      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
        select: {
          telegramUsername: true,
          telegramId: true,
        },
      });

      // Стратегия 1: Telegram username + N символов (ОСНОВНАЯ СТРАТЕГИЯ)
      if (user?.telegramUsername && alternatives.length < maxAlternatives) {
        const telegramUsername = user.telegramUsername.trim();

        // Добавляем цифры к Telegram username
        for (let i = 1; i <= 3 && alternatives.length < maxAlternatives; i++) {
          const randomNum = Math.floor(Math.random() * 1000);
          const candidate = `${telegramUsername}${randomNum}`;

          if (
            candidate.length <= 50 &&
            (await this.isUsernameAvailable(candidate))
          ) {
            alternatives.push(candidate);
          }
        }

        // Добавляем буквы к Telegram username
        for (let i = 1; i <= 2 && alternatives.length < maxAlternatives; i++) {
          const randomLetter = String.fromCharCode(
            97 + Math.floor(Math.random() * 26),
          ); // a-z
          const candidate = `${telegramUsername}${randomLetter}`;

          if (
            candidate.length <= 50 &&
            (await this.isUsernameAvailable(candidate))
          ) {
            alternatives.push(candidate);
          }
        }
      }

      // Стратегия 2: Telegram ID + N символов (если нет Telegram username)
      if (user?.telegramId && alternatives.length < maxAlternatives) {
        const telegramId = user.telegramId;

        // Добавляем цифры к Telegram ID
        for (let i = 1; i <= 2 && alternatives.length < maxAlternatives; i++) {
          const randomNum = Math.floor(Math.random() * 100);
          const candidate = `tg_${telegramId}_${randomNum}`;

          if (
            candidate.length <= 50 &&
            (await this.isUsernameAvailable(candidate))
          ) {
            alternatives.push(candidate);
          }
        }
      }

      // Стратегия 3: Базовый username + N символов (fallback)
      if (alternatives.length < maxAlternatives) {
        // Добавляем цифры к базовому username
        for (let i = 1; i <= 2 && alternatives.length < maxAlternatives; i++) {
          const randomNum = Math.floor(Math.random() * 1000);
          const candidate = `${baseUsername}${randomNum}`;

          if (
            candidate.length <= 50 &&
            (await this.isUsernameAvailable(candidate))
          ) {
            alternatives.push(candidate);
          }
        }

        // Добавляем год к базовому username
        if (alternatives.length < maxAlternatives) {
          const currentYear = new Date().getFullYear().toString().slice(-2);
          const candidate = `${baseUsername}${currentYear}`;

          if (
            candidate.length <= 50 &&
            (await this.isUsernameAvailable(candidate))
          ) {
            alternatives.push(candidate);
          }
        }
      }

      return alternatives.slice(0, maxAlternatives);
    } catch (error) {
      this.logger.error(
        `Error generating username alternatives: ${(error as Error).message}`,
      );
      return [];
    }
  }

  /**
   * Выполняет операцию, преобразуя непредвиденные ошибки в RpcException.
   */
  private async withRpcError<T>(
    operation: () => Promise<T>,
    message: string,
  ): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      this.logger.error(`${message}: ${(error as Error).message}`);

      if (error instanceof RpcException) {
        throw error;
      }

      throw new RpcException({
        code: status.INTERNAL,
        message,
      });
    }
  }

  /**
   * Проверяет, доступен ли username
   */
  private async isUsernameAvailable(username: string): Promise<boolean> {
    try {
      const existingUser = await this.prismaService.user.findUnique({
        where: { username: username },
      });
      return !existingUser;
    } catch (error) {
      this.logger.error(
        `Error checking username availability: ${(error as Error).message}`,
      );
      return false;
    }
  }

  /**
   * Предлагает альтернативные username для желаемого username
   */
  async suggestUsernameAlternatives(
    userId: string,
    desiredUsername: string,
    maxAlternatives: number = 5,
  ): Promise<string[]> {
    // Валидация входных данных
    if (!userId || userId.trim().length === 0 || userId.length > 100) {
      throw new RpcException({
        code: status.INVALID_ARGUMENT,
        message: 'Invalid user ID',
      });
    }

    if (
      !desiredUsername ||
      desiredUsername.trim().length === 0 ||
      desiredUsername.length > 50
    ) {
      throw new RpcException({
        code: status.INVALID_ARGUMENT,
        message: 'Invalid desired username',
      });
    }

    if (maxAlternatives < 1 || maxAlternatives > 10) {
      throw new RpcException({
        code: status.INVALID_ARGUMENT,
        message: 'Max alternatives must be between 1 and 10',
      });
    }

    // Проверяем, что пользователь существует
    const user = await this.withRpcError(
      () => this.prismaService.user.findUnique({ where: { id: userId } }),
      'Failed to suggest username alternatives',
    );

    if (!user) {
      throw new RpcException({
        code: status.NOT_FOUND,
        message: 'User not found',
      });
    }

    // Валидируем желаемый username
    const usernameValidation = this.validateUserUsername(desiredUsername);
    if (!usernameValidation.valid) {
      throw new RpcException({
        code: status.INVALID_ARGUMENT,
        message: `Desired username validation failed: ${usernameValidation.errors.join(', ')}`,
      });
    }

    // Генерируем альтернативы
    const alternatives = await this.withRpcError(
      () =>
        this.generateUsernameAlternatives(
          desiredUsername,
          userId,
          maxAlternatives,
        ),
      'Failed to suggest username alternatives',
    );

    this.logger.log(
      `✅ [USER] Generated ${alternatives.length} alternatives for username: ${desiredUsername}`,
    );
    return alternatives;
  }
}
