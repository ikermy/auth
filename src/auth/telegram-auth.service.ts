import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma.service';
import { JwtService } from '@nestjs/jwt';
import { RpcException } from '@nestjs/microservices';
import { status } from '@grpc/grpc-js';
import { OracleUsernameService } from './services/oracle-username.service';
import { OracleIdentityService } from './services/oracle-identity.service';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';
import * as crypto from 'crypto';

interface TelegramAuthData {
  telegramId: string;
  firstName: string;
  lastName?: string;
  username?: string;
  photoUrl?: string;
  authDate: string;
  hash: string;
}

interface TelegramUser {
  id: string;
  first_name: string;
  last_name?: string;
  username?: string;
  photo_url?: string;
}

// Интерфейсы для Telegram Bot API (согласно официальной документации)
interface TelegramBotAPIUser {
  id: number;
  is_bot: boolean;
  first_name: string;
  last_name?: string;
  username?: string;
  language_code?: string;
  is_premium?: boolean;
  added_to_attachment_menu?: boolean;
  can_join_groups?: boolean;
  can_read_all_group_messages?: boolean;
  supports_inline_queries?: boolean;
}

interface TelegramBotAPIMessage {
  message_id: number;
  from?: TelegramBotAPIUser;
  date: number;
  chat: {
    id: number;
    type: string;
    title?: string;
    username?: string;
    first_name?: string;
    last_name?: string;
  };
  text?: string;
  // Другие поля сообщения...
}

interface TelegramUpdate {
  update_id: number;
  message?: TelegramBotAPIMessage;
  edited_message?: TelegramBotAPIMessage;
  channel_post?: TelegramBotAPIMessage;
  edited_channel_post?: TelegramBotAPIMessage;
  // Другие типы обновлений...
}

interface TelegramBotAPIResponse<T> {
  ok: boolean;
  result?: T;
  error_code?: number;
  description?: string;
}

interface AuthenticatedUser {
  id: string;
  email: string;
  telegramId: string;
  telegramUsername?: string;
  telegramFirstName?: string;
  telegramLastName?: string;
  telegramPhotoUrl?: string;
  isTelegramVerified: boolean;
}

interface AuthResult {
  user: AuthenticatedUser;
  isNewUser: boolean;
}

@Injectable()
export class TelegramAuthService {
  private readonly logger = new Logger(TelegramAuthService.name);
  private readonly AUTH_DATE_EXPIRY_HOURS = 24; // Telegram auth data expires in 24 hours

  constructor(
    private readonly prismaService: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly oracleUsernameService: OracleUsernameService,
    private readonly oracleIdentityService: OracleIdentityService,
    private readonly httpService: HttpService,
  ) {}

  private get botToken(): string {
    const token = this.configService.get<string>('TELEGRAM_BOT_TOKEN');
    if (!token) {
      throw new Error('TELEGRAM_BOT_TOKEN is not configured');
    }
    return token;
  }

  validateTelegramAuth(authData: TelegramAuthData): boolean {
    // Валидация входных данных
    if (!authData || typeof authData !== 'object') {
      return false;
    }

    if (
      !authData.telegramId ||
      authData.telegramId.trim().length === 0 ||
      authData.telegramId.length > 50
    ) {
      return false;
    }

    if (
      !authData.firstName ||
      authData.firstName.trim().length === 0 ||
      authData.firstName.length > 100
    ) {
      return false;
    }

    if (authData.lastName && authData.lastName.length > 100) {
      return false;
    }

    if (authData.username && authData.username.length > 50) {
      return false;
    }

    if (authData.photoUrl && authData.photoUrl.length > 500) {
      return false;
    }

    if (
      !authData.authDate ||
      !authData.hash ||
      authData.authDate.length > 20 ||
      authData.hash.length > 100
    ) {
      return false;
    }

    try {
      this.logger.log(
        `Validating Telegram auth for user ${authData.telegramId}`,
      );

      // Проверяем время authDate
      if (!this.isAuthDateValid(authData.authDate)) {
        this.logger.warn(
          `Expired Telegram auth data for user ${authData.telegramId}. Auth date: ${authData.authDate}`,
        );
        return false;
      }

      // Проверяем подпись
      const isValid = this.validateTelegramSignature(authData);

      if (!isValid) {
        this.logger.warn(
          `Invalid Telegram signature for user ${authData.telegramId}`,
        );
        return false;
      }

      return true;
    } catch (error) {
      this.logger.error(
        `Error validating Telegram auth: ${(error as Error).message}`,
      );
      return false;
    }
  }

  private isAuthDateValid(authDate: string): boolean {
    try {
      // Валидация входных данных
      if (!authDate || authDate.trim().length === 0 || authDate.length > 20) {
        return false;
      }

      const authTimestamp = parseInt(authDate, 10);

      // Проверка на NaN и валидность
      if (
        isNaN(authTimestamp) ||
        authTimestamp <= 0 ||
        authTimestamp > 9999999999
      ) {
        return false;
      }

      const currentTimestamp = Math.floor(Date.now() / 1000);
      const expiryTimestamp =
        authTimestamp + this.AUTH_DATE_EXPIRY_HOURS * 60 * 60;

      return currentTimestamp <= expiryTimestamp;
    } catch (error) {
      this.logger.error(`Invalid auth date format: ${authDate}`);
      return false;
    }
  }

  private validateTelegramSignature(authData: TelegramAuthData): boolean {
    // Проверка подписи Telegram OAuth
    const dataCheckString = this.buildDataCheckString(authData);
    const secretKey = crypto
      .createHash('sha256')
      .update(this.botToken)
      .digest();

    // Проверяем подпись Telegram OAuth
    const expectedHash = crypto
      .createHmac('sha256', secretKey)
      .update(dataCheckString)
      .digest('hex');

    // Timing-safe проверка подписи
    const isValidSignature = this.timingSafeCompare(
      authData.hash,
      expectedHash,
    );

    // Безопасное логирование без раскрытия чувствительных данных
    if (!isValidSignature) {
      this.logger.warn(
        `Invalid Telegram signature for user ${authData.telegramId}`,
      );
    }

    return isValidSignature;
  }

  // Timing-safe сравнение строк
  private timingSafeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false;
    }

    const aBuffer = Buffer.from(a, 'utf8');
    const bBuffer = Buffer.from(b, 'utf8');

    return crypto.timingSafeEqual(aBuffer, bBuffer);
  }

  private buildDataCheckString(authData: TelegramAuthData): string {
    const params = new Map<string, string>();
    params.set('auth_date', authData.authDate || '');
    params.set('first_name', authData.firstName || '');
    if (authData.lastName) params.set('last_name', authData.lastName);
    if (authData.username) params.set('username', authData.username);
    if (authData.photoUrl) params.set('photo_url', authData.photoUrl);
    params.set('id', authData.telegramId || '');

    const result = Array.from(params.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}=${value}`)
      .join('\n');

    // Валидация длины результирующей строки
    if (result.length > 10000) {
      // Максимум 10KB
      throw new Error('Data check string too long');
    }

    return result;
  }

  async authenticateOrCreateUser(
    authData: TelegramAuthData,
  ): Promise<AuthResult> {
    try {
      // Валидация входных данных
      if (!authData.telegramId || authData.telegramId.trim().length === 0) {
        throw new Error('Invalid telegram ID');
      }

      if (!authData.firstName || authData.firstName.trim().length === 0) {
        throw new Error('Invalid first name');
      }

      // Проверяем существующего пользователя по Telegram ID
      let user = await this.prismaService.user.findUnique({
        where: { telegramId: authData.telegramId },
      });

      let isNewUser = false;

      if (!user) {
        // Создаем нового пользователя с безопасными данными
        const secureEmail = this.generateSecureEmail(authData.telegramId);
        const securePassword = this.generateSecurePassword();
        const oracleUsername =
          this.oracleUsernameService.generateOracleUsername(
            authData.telegramId,
            authData.username,
          );

        user = await this.prismaService.user.create({
          data: {
            telegramId: authData.telegramId,
            telegramUsername: authData.username,
            telegramFirstName: authData.firstName,
            telegramLastName: authData.lastName,
            telegramPhotoUrl: authData.photoUrl,
            isTelegramVerified: true,
            oracleUsername: oracleUsername,
            email: secureEmail,
            password: securePassword,
          },
        });
        isNewUser = true;
        this.logger.log(
          `Created new user via Telegram: ${authData.telegramId} with Oracle username: ${oracleUsername}`,
        );
      } else {
        // Обновляем данные существующего пользователя
        const newOracleUsername =
          this.oracleUsernameService.generateOracleUsername(
            authData.telegramId,
            authData.username,
          );

        user = await this.prismaService.user.update({
          where: { id: user.id },
          data: {
            telegramUsername: authData.username,
            telegramFirstName: authData.firstName,
            telegramLastName: authData.lastName,
            telegramPhotoUrl: authData.photoUrl,
            isTelegramVerified: true,
            oracleUsername: newOracleUsername, // Синхронизируем Oracle username с Telegram
            lastLoginAt: new Date(),
          },
        });
        this.logger.log(
          `Updated existing user via Telegram: ${authData.telegramId} with Oracle username: ${newOracleUsername}`,
        );
      }

      const authenticatedUser: AuthenticatedUser = {
        id: user.id,
        email: user.email,
        telegramId: user.telegramId || '',
        telegramUsername: user.telegramUsername || undefined,
        telegramFirstName: user.telegramFirstName || undefined,
        telegramLastName: user.telegramLastName || undefined,
        telegramPhotoUrl: user.telegramPhotoUrl || undefined,
        isTelegramVerified: user.isTelegramVerified,
      };

      return { user: authenticatedUser, isNewUser };
    } catch (error) {
      this.logger.error(
        `Error in authenticateOrCreateUser: ${(error as Error).message}`,
      );
      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to authenticate or create user',
      });
    }
  }

  private generateSecureEmail(telegramId: string): string {
    // Генерируем безопасный email с префиксом tg_ для единообразия
    const randomSuffix = crypto.randomBytes(16).toString('hex');
    return `tg_${telegramId}_${randomSuffix}@secure.local`;
  }

  private generateSecurePassword(): string {
    return crypto.randomBytes(64).toString('hex');
  }

  async generateTokens(
    userId: string,
    email: string,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    try {
      // Валидация входных данных
      if (!userId || userId.trim().length === 0 || userId.length > 100) {
        throw new Error('Invalid user ID for token generation');
      }

      if (!email || email.trim().length === 0 || email.length > 255) {
        throw new Error('Invalid email for token generation');
      }

      const payload = {
        sub: userId,
        email,
        authType: 'telegram',
      };

      const accessToken = await this.jwtService.signAsync(payload, {
        expiresIn: this.configService.getOrThrow<string>('JWT_EXPIRES_IN'),
      });

      const refreshToken = await this.jwtService.signAsync(payload, {
        expiresIn: this.configService.getOrThrow<string>('JWT_REFRESH_IN'),
      });

      return { accessToken, refreshToken };
    } catch (error) {
      this.logger.error(`Error generating tokens: ${(error as Error).message}`);
      throw error;
    }
  }

  async linkTelegramToExistingAccount(
    userId: string,
    authData: TelegramAuthData,
  ): Promise<boolean> {
    try {
      // Проверяем, не привязан ли уже этот Telegram ID к другому аккаунту
      const existingTelegramUser = await this.prismaService.user.findUnique({
        where: { telegramId: authData.telegramId },
      });

      if (existingTelegramUser && existingTelegramUser.id !== userId) {
        throw new Error(
          'This Telegram account is already linked to another user',
        );
      }

      // Проверяем существование пользователя перед обновлением
      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new Error('User not found');
      }

      // Привязываем Telegram к существующему аккаунту
      const oracleUsername = this.oracleUsernameService.generateOracleUsername(
        authData.telegramId,
        authData.username,
      );

      await this.prismaService.user.update({
        where: { id: userId },
        data: {
          telegramId: authData.telegramId,
          telegramUsername: authData.username,
          telegramFirstName: authData.firstName,
          telegramLastName: authData.lastName,
          telegramPhotoUrl: authData.photoUrl,
          isTelegramVerified: true,
          oracleUsername: oracleUsername, // Устанавливаем Oracle username
        },
      });

      this.logger.log(
        `Linked Telegram account ${authData.telegramId} to user ${userId}`,
      );
      return true;
    } catch (error) {
      this.logger.error(
        `Error linking Telegram account: ${(error as Error).message}`,
      );
      throw new RpcException({
        code: status.INTERNAL,
        message: (error as Error).message,
      });
    }
  }

  async getTelegramUserInfo(telegramId: string): Promise<TelegramUser | null> {
    try {
      const user = await this.prismaService.user.findUnique({
        where: { telegramId },
        select: {
          telegramId: true,
          telegramFirstName: true,
          telegramLastName: true,
          telegramUsername: true,
          telegramPhotoUrl: true,
        },
      });

      if (!user) return null;

      return {
        id: user.telegramId || '',
        first_name: user.telegramFirstName || '',
        last_name: user.telegramLastName || undefined,
        username: user.telegramUsername || undefined,
        photo_url: user.telegramPhotoUrl || undefined,
      };
    } catch (error) {
      this.logger.error(
        `Error getting Telegram user info: ${(error as Error).message}`,
      );
      return null;
    }
  }

  // Получение актуальных данных пользователя из Telegram API
  // ВАЖНО: Telegram Bot API НЕ предоставляет методов для получения информации о пользователе по user_id
  // без предварительного взаимодействия с ботом. Данные доступны только через getUpdates или webhook.
  async getTelegramUserFromAPI(telegramId: string): Promise<{
    username?: string;
    firstName?: string;
    lastName?: string;
    photoUrl?: string;
  } | null> {
    try {
      this.logger.log(
        `📱 [TELEGRAM] Attempting to fetch user data from API for user ${telegramId}`,
      );

      // Получаем токен бота
      const botToken = this.botToken;
      const apiUrl = `https://api.telegram.org/bot${botToken}`;

      // 1. Пытаемся получить обновления через getUpdates
      // Это единственный способ получить данные о пользователях в Telegram Bot API
      let userData: TelegramBotAPIUser | null = null;

      try {
        const updatesResponse = await firstValueFrom(
          this.httpService.get<TelegramBotAPIResponse<TelegramUpdate[]>>(
            `${apiUrl}/getUpdates`,
            {
              params: {
                limit: 100, // Получаем последние 100 обновлений
                timeout: 0, // Не ждем новых обновлений
              },
              timeout: 10000, // 10 секунд таймаут
            },
          ),
        );

        if ((updatesResponse as any).data.ok && (updatesResponse as any).data.result) {
          // Ищем пользователя с нужным telegramId в обновлениях
          for (const update of (updatesResponse as any).data.result) {
            if (
              update.message &&
              update.message.from &&
              update.message.from.id.toString() === telegramId
            ) {
              userData = update.message.from;
              this.logger.debug(
                `📱 [TELEGRAM] Found user data in updates for ${telegramId}`,
              );
              break;
            }
          }
        }
      } catch (updatesError) {
        this.logger.warn(
          `📱 [TELEGRAM] getUpdates failed for user ${telegramId}: ${(updatesError as Error).message}`,
        );
      }

      // 2. Если нашли данные пользователя в обновлениях, возвращаем их
      if (userData) {
        const result = {
          username: userData.username,
          firstName: userData.first_name,
          lastName: userData.last_name,
          photoUrl: undefined, // Telegram Bot API не предоставляет прямого доступа к фото профиля
        };

        this.logger.log(
          `📱 [TELEGRAM] Successfully retrieved user data for ${telegramId}: ${JSON.stringify(result)}`,
        );
        return result;
      }

      // 3. Если пользователь не найден в обновлениях, это означает что он не взаимодействовал с ботом
      this.logger.warn(
        `📱 [TELEGRAM] User ${telegramId} not found in bot updates. User may not have interacted with the bot.`,
      );
      return null;
    } catch (error) {
      this.logger.error(
        `📱 [TELEGRAM] Error getting user data from API for ${telegramId}: ${(error as Error).message}`,
      );
      return null;
    }
  }

  // Обновление Oracle username при логине через Telegram
  async updateOracleUsernameOnLogin(telegramId: string): Promise<void> {
    try {
      // Получаем пользователя из БД
      const user = await this.prismaService.user.findUnique({
        where: { telegramId },
        select: {
          id: true,
          telegramUsername: true,
          oracleUsername: true,
        },
      });

      if (!user) {
        return;
      }

      // Генерируем новый Oracle username на основе текущих данных
      const newOracleUsername =
        this.oracleUsernameService.generateOracleUsername(
          telegramId,
          user.telegramUsername || undefined,
        );

      // Проверяем, нужно ли обновлять
      if (newOracleUsername !== user.oracleUsername) {
        // Проверяем, что новый username не занят другим пользователем
        const existingUser = await this.prismaService.user.findUnique({
          where: { oracleUsername: newOracleUsername },
        });

        if (!existingUser || existingUser.id === user.id) {
          // Обновляем Oracle username
          await this.prismaService.user.update({
            where: { id: user.id },
            data: {
              oracleUsername: newOracleUsername,
            },
          });

          this.logger.log(
            `🔄 [ORACLE] Updated username for user ${user.id}: ${user.oracleUsername} -> ${newOracleUsername}`,
          );
        } else {
          // Генерируем альтернативные username
          const alternatives =
            await this.oracleIdentityService.generateUsernameAlternatives(
              newOracleUsername,
              user.id,
              3,
            );

          this.logger.warn(
            `⚠️ [ORACLE] Cannot update username for user ${user.id}: ${newOracleUsername} is already taken. Alternatives: ${alternatives.join(', ')}`,
          );
        }
      }
    } catch (error) {
      this.logger.error(
        `Error updating Oracle username on login: ${(error as Error).message}`,
      );
    }
  }
}
