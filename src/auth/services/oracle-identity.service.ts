import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../prisma.service';
import { RpcException } from '@nestjs/microservices';
import { status } from '@grpc/grpc-js';

export interface OracleIdentity {
  userId: string; // ID (неизменяемый)
  oracleUsername?: string; // Username (изменяемый, уникальный)
  oracleNickName?: string; // NickName (изменяемый, неуникальный)
}

@Injectable()
export class OracleIdentityService {
  private readonly logger = new Logger(OracleIdentityService.name);

  constructor(private readonly prismaService: PrismaService) {}

  /**
   * Получает Oracle идентификаторы пользователя
   */
  async getOracleIdentity(userId: string): Promise<OracleIdentity> {
    try {
      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
        select: {
          id: true,
          oracleUsername: true,
          oracleNickName: true,
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
        oracleUsername: user.oracleUsername || undefined,
        oracleNickName: user.oracleNickName || undefined,
      };
    } catch (error) {
      this.logger.error(
        `Error getting Oracle identity: ${(error as Error).message}`,
      );

      if (error instanceof RpcException) {
        throw error;
      }

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to get Oracle identity',
      });
    }
  }

  /**
   * Изменяет Oracle Username
   */
  async changeOracleUsername(
    userId: string,
    newUsername: string,
  ): Promise<string> {
    try {
      // Валидация входных данных
      if (!userId || userId.trim().length === 0 || userId.length > 100) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid user ID',
        });
      }

      if (
        !newUsername ||
        newUsername.trim().length === 0 ||
        newUsername.length > 50
      ) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid username',
        });
      }

      // Валидация формата username
      const usernameValidation = this.validateOracleUsername(newUsername);
      if (!usernameValidation.valid) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: `Username validation failed: ${usernameValidation.errors.join(', ')}`,
        });
      }

      // Проверяем, что пользователь существует
      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new RpcException({
          code: status.NOT_FOUND,
          message: 'User not found',
        });
      }

      // Проверяем, что новый username не занят другим пользователем
      const existingUser = await this.prismaService.user.findUnique({
        where: { oracleUsername: newUsername },
      });

      if (existingUser && existingUser.id !== userId) {
        // Генерируем альтернативные username
        const alternatives = await this.generateUsernameAlternatives(
          newUsername,
          userId,
          5,
        );

        throw new RpcException({
          code: status.ALREADY_EXISTS,
          message: 'Oracle username is already taken',
          details: JSON.stringify({
            hasAlternatives: alternatives.length > 0,
            alternativeUsernames: alternatives,
          }),
        });
      }

      // Обновляем Oracle username
      await this.prismaService.user.update({
        where: { id: userId },
        data: {
          oracleUsername: newUsername,
        },
      });

      this.logger.log(
        `✅ [ORACLE] Username changed for user ${userId}: ${user.oracleUsername} -> ${newUsername}`,
      );
      return newUsername;
    } catch (error) {
      this.logger.error(
        `Error changing Oracle username: ${(error as Error).message}`,
      );

      if (error instanceof RpcException) {
        throw error;
      }

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to change Oracle username',
      });
    }
  }

  /**
   * Изменяет Oracle NickName
   */
  async changeOracleNickName(
    userId: string,
    newNickName: string,
  ): Promise<string> {
    try {
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
      const nicknameValidation = this.validateOracleNickName(newNickName);
      if (!nicknameValidation.valid) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: `Nickname validation failed: ${nicknameValidation.errors.join(', ')}`,
        });
      }

      // Проверяем, что пользователь существует
      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new RpcException({
          code: status.NOT_FOUND,
          message: 'User not found',
        });
      }

      // Обновляем Oracle nickname (nickname не уникален, поэтому проверка на существование не нужна)
      await this.prismaService.user.update({
        where: { id: userId },
        data: {
          oracleNickName: newNickName,
        },
      });

      this.logger.log(
        `✅ [ORACLE] NickName changed for user ${userId}: ${user.oracleNickName} -> ${newNickName}`,
      );
      return newNickName;
    } catch (error) {
      this.logger.error(
        `Error changing Oracle nickname: ${(error as Error).message}`,
      );

      if (error instanceof RpcException) {
        throw error;
      }

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to change Oracle nickname',
      });
    }
  }

  /**
   * Валидирует Oracle Username
   */
  private validateOracleUsername(username: string): {
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
      'oracle',
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
   * Валидирует Oracle NickName
   */
  private validateOracleNickName(nickName: string): {
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
   * Проверяет, может ли пользователь изменить Oracle Username
   * (например, если у него привязан Telegram, то изменение может быть ограничено)
   */
  async canChangeOracleUsername(
    userId: string,
  ): Promise<{ canChange: boolean; reason?: string }> {
    try {
      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
        select: {
          telegramId: true,
          isTelegramVerified: true,
        },
      });

      if (!user) {
        return { canChange: false, reason: 'User not found' };
      }

      // Если у пользователя привязан Telegram, то Oracle Username должен синхронизироваться с Telegram
      if (user.telegramId && user.isTelegramVerified) {
        return {
          canChange: false,
          reason:
            'Oracle username is synchronized with Telegram. Use syncOracleUsername to update it.',
        };
      }

      return { canChange: true };
    } catch (error) {
      this.logger.error(
        `Error checking Oracle username change permission: ${(error as Error).message}`,
      );
      return { canChange: false, reason: 'Internal error' };
    }
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
   * Проверяет, доступен ли username
   */
  private async isUsernameAvailable(username: string): Promise<boolean> {
    try {
      const existingUser = await this.prismaService.user.findUnique({
        where: { oracleUsername: username },
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
    try {
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
      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new RpcException({
          code: status.NOT_FOUND,
          message: 'User not found',
        });
      }

      // Валидируем желаемый username
      const usernameValidation = this.validateOracleUsername(desiredUsername);
      if (!usernameValidation.valid) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: `Desired username validation failed: ${usernameValidation.errors.join(', ')}`,
        });
      }

      // Генерируем альтернативы
      const alternatives = await this.generateUsernameAlternatives(
        desiredUsername,
        userId,
        maxAlternatives,
      );

      this.logger.log(
        `✅ [ORACLE] Generated ${alternatives.length} alternatives for username: ${desiredUsername}`,
      );
      return alternatives;
    } catch (error) {
      this.logger.error(
        `Error suggesting username alternatives: ${(error as Error).message}`,
      );

      if (error instanceof RpcException) {
        throw error;
      }

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to suggest username alternatives',
      });
    }
  }
}
