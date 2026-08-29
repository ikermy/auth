import { Injectable, Logger } from '@nestjs/common';
import {
  LoginRequest,
  LoginResponse,
  RegisterRequest,
  RegisterResponse,
  EnableSeedPhraseRequest,
  EnableSeedPhraseResponse,
  VerifySeedPhraseRequest,
  VerifySeedPhraseResponse,
  DisableSeedPhraseRequest,
  DisableSeedPhraseResponse,
  GetSeedPhraseStatusRequest,
  GetSeedPhraseStatusResponse,
  ChangePasswordRequest,
  ChangePasswordResponse,
  ChangeEmailRequest,
  ChangeEmailResponse,
  ChangeTelegramAccountRequest,
  ChangeTelegramAccountResponse,
  TerminateAllSessionsRequest,
  TerminateAllSessionsResponse,
  LinkEmailRequest,
  LinkEmailResponse,
  SyncOracleUsernameRequest,
  SyncOracleUsernameResponse,
  ChangeOracleUsernameRequest,
  ChangeOracleUsernameResponse,
  ChangeOracleNickNameRequest,
  ChangeOracleNickNameResponse,
  GetOracleIdentityRequest,
  GetOracleIdentityResponse,
  SuggestOracleUsernameAlternativesRequest,
  SuggestOracleUsernameAlternativesResponse,
} from './auth';
import { PrismaService } from '../prisma.service';
import { JwtService } from '@nestjs/jwt';
import { RpcException } from '@nestjs/microservices';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { status } from '@grpc/grpc-js';
import { EncryptionService } from '../security/services/encryption.service';
import { OracleUsernameService } from './services/oracle-username.service';
import { OracleIdentityService } from './services/oracle-identity.service';
import * as crypto from 'crypto';

interface GrpcError {
  code: number;
  message: string;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly prismaService: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly encryptionService: EncryptionService,
    private readonly oracleUsernameService: OracleUsernameService,
    private readonly oracleIdentityService: OracleIdentityService,
  ) {}
  async login(data: LoginRequest): Promise<LoginResponse> {
    const { email, password } = data;

    const user = await this.prismaService.user.findUnique({
      where: {
        email,
      },
    });

    if (!user) {
      const error: GrpcError = {
        code: status.NOT_FOUND,
        message: 'User not found',
      };
      throw new RpcException(error);
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      const error: GrpcError = {
        code: status.PERMISSION_DENIED,
        message: 'Invalid password',
      };
      throw new RpcException(error);
    }

    const { accessToken, refreshToken } = await this.generateTokens(
      user.id,
      user.email,
    );
    return {
      accessToken,
      refreshToken,
    };
  }

  async register(data: RegisterRequest): Promise<RegisterResponse> {
    try {
      const { email, password } = data;

      const existingUser = await this.prismaService.user.findUnique({
        where: {
          email,
        },
      });

      if (existingUser) {
        const error: GrpcError = {
          code: status.ALREADY_EXISTS,
          message: 'User already exists',
        };
        throw new RpcException(error);
      }

      const salt = await bcrypt.genSalt(14);
      const hashedPassword = await bcrypt.hash(password, salt);

      const newUser = await this.prismaService.user.create({
        data: {
          email,
          password: hashedPassword,
        },
      });

      const { accessToken, refreshToken } = await this.generateTokens(
        newUser.id,
        newUser.email,
      );
      return {
        accessToken,
        refreshToken,
      };
    } catch (error) {
      this.logger.error(`Registration error: ${(error as Error).message}`);

      if (error instanceof RpcException) {
        throw error;
      }

      const grpcError: GrpcError = {
        code: status.INTERNAL,
        message: 'Registration failed',
      };
      throw new RpcException(grpcError);
    }
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
      };

      const accessToken = await this.jwtService.signAsync(payload, {
        expiresIn: this.configService.getOrThrow<string>('JWT_EXPIRES_IN'),
      });

      const refreshToken = await this.jwtService.signAsync(payload, {
        expiresIn: this.configService.getOrThrow<string>('JWT_REFRESH_IN'),
      });

      // Шифруем токены перед возвратом
      const encryptedAccessToken = this.encryptionService.encrypt(accessToken);
      const encryptedRefreshToken =
        this.encryptionService.encrypt(refreshToken);

      return {
        accessToken: encryptedAccessToken,
        refreshToken: encryptedRefreshToken,
      };
    } catch (error) {
      this.logger.error(`Token generation error: ${(error as Error).message}`);
      throw error;
    }
  }

  async refreshToken(
    refreshToken: string,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    try {
      const payload: { sub: string; type?: string } =
        await this.jwtService.verifyAsync(refreshToken, {
          secret: this.configService.getOrThrow<string>(
            'JWT_SUPER_SECRET_WORD',
          ),
        });

      // Проверяем тип токена
      if (payload.type && payload.type !== 'refresh') {
        const error: GrpcError = {
          code: status.PERMISSION_DENIED,
          message: 'Invalid token type for refresh',
        };
        throw new RpcException(error);
      }

      const user = await this.prismaService.user.findUnique({
        where: {
          id: payload.sub,
        },
      });

      if (!user) {
        const error: GrpcError = {
          code: status.NOT_FOUND,
          message: 'User not found',
        };
        throw new RpcException(error);
      }

      return await this.generateTokens(user.id, user.email);
    } catch (error) {
      // Безопасная обработка ошибок
      this.logger.error(`Token refresh error: ${(error as Error).message}`);

      const grpcError: GrpcError = {
        code: status.PERMISSION_DENIED,
        message: 'Invalid refresh token',
      };
      throw new RpcException(grpcError);
    }
  }

  async enableSeedPhrase(
    data: EnableSeedPhraseRequest,
  ): Promise<EnableSeedPhraseResponse> {
    try {
      const { userId, seedPhrase } = data;

      // Валидация входных данных
      if (!userId || userId.trim().length === 0 || userId.length > 100) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid user ID',
        });
      }

      if (
        !seedPhrase ||
        seedPhrase.trim().length === 0 ||
        seedPhrase.length > 1000
      ) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid seed phrase',
        });
      }

      // Получаем пользователя
      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new RpcException({
          code: status.NOT_FOUND,
          message: 'User not found',
        });
      }

      if (user.seedPhraseEnabled) {
        throw new RpcException({
          code: status.FAILED_PRECONDITION,
          message: 'Seed phrase already enabled for this user',
        });
      }

      // Проверяем сложность seed фразы (минимум 12 слов)
      const words = seedPhrase.trim().split(/\s+/);
      if (words.length < 12) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Seed phrase must contain at least 12 words',
        });
      }

      // Проверяем формат seed фразы (только буквы и пробелы)
      const seedPhraseRegex = /^[a-zA-Z\s]+$/;
      if (!seedPhraseRegex.test(seedPhrase.trim())) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Seed phrase must contain only letters and spaces',
        });
      }

      // Генерируем соль и хешируем seed фразу
      const salt = crypto.randomBytes(32).toString('hex');
      const hash = await bcrypt.hash(seedPhrase, 14);

      // Сохраняем соль и хеш в базу
      await this.prismaService.user.update({
        where: { id: userId },
        data: {
          seedPhraseEnabled: true,
          seedPhraseHash: hash,
          seedPhraseSalt: salt,
          seedPhraseAttempts: 0,
          seedPhraseLockedUntil: null,
          seedPhraseLastVerifiedAt: new Date(), // Устанавливаем время первой проверки
          seedPhraseVerificationCount: 1, // Первая успешная проверка
        },
      });

      this.logger.log(`🔐 [SEED] Enabled for user ${userId}`);
      return {
        success: true,
        message: 'Seed phrase enabled successfully',
      };
    } catch (error) {
      this.logger.error(
        `Seed phrase enable error: ${(error as Error).message}`,
      );

      if (error instanceof RpcException) {
        throw error;
      }

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to enable seed phrase',
      });
    }
  }

  async verifySeedPhrase(
    data: VerifySeedPhraseRequest,
  ): Promise<VerifySeedPhraseResponse> {
    try {
      const { userId, seedPhrase } = data;

      // Валидация входных данных
      if (!userId || userId.trim().length === 0 || userId.length > 100) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid user ID',
        });
      }

      if (
        !seedPhrase ||
        seedPhrase.trim().length === 0 ||
        seedPhrase.length > 1000
      ) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid seed phrase',
        });
      }

      // Получаем пользователя
      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new RpcException({
          code: status.NOT_FOUND,
          message: 'User not found',
        });
      }

      if (!user.seedPhraseEnabled || !user.seedPhraseHash) {
        throw new RpcException({
          code: status.FAILED_PRECONDITION,
          message: 'Seed phrase not enabled for this user',
        });
      }

      // Проверяем блокировку
      if (
        user.seedPhraseLockedUntil &&
        new Date() < user.seedPhraseLockedUntil
      ) {
        throw new RpcException({
          code: status.RESOURCE_EXHAUSTED,
          message: `Account locked until ${user.seedPhraseLockedUntil.toISOString()}`,
        });
      }

      // Проверяем seed фразу
      const isValid = await bcrypt.compare(seedPhrase, user.seedPhraseHash);

      if (isValid) {
        // Сбрасываем счетчик попыток и блокировку, обновляем статистику
        await this.prismaService.user.update({
          where: { id: userId },
          data: {
            seedPhraseAttempts: 0,
            seedPhraseLockedUntil: null,
            seedPhraseLastVerifiedAt: new Date(), // Обновляем время последней проверки
            seedPhraseVerificationCount: { increment: 1 }, // Увеличиваем счетчик проверок
          },
        });

        // Генерируем специальный токен для доступа к Oracle
        const oracleToken = await this.generateOracleAccessToken(
          userId,
          user.email,
        );

        this.logger.log(`🔐 [SEED] Verified for user ${userId}`);
        return {
          success: true,
          message: 'Seed phrase verified successfully',
          oracleAccessToken: this.encryptionService.encrypt(oracleToken),
        };
      } else {
        // Увеличиваем счетчик попыток
        const newAttempts = user.seedPhraseAttempts + 1;
        const maxAttempts = 5;
        const lockoutDuration = 15 * 60 * 1000; // 15 минут

        let lockedUntil = null;
        if (newAttempts >= maxAttempts) {
          lockedUntil = new Date(Date.now() + lockoutDuration);
        }

        await this.prismaService.user.update({
          where: { id: userId },
          data: {
            seedPhraseAttempts: newAttempts,
            seedPhraseLockedUntil: lockedUntil,
          },
        });

        if (lockedUntil) {
          throw new RpcException({
            code: status.RESOURCE_EXHAUSTED,
            message: `Too many failed attempts. Account locked until ${lockedUntil.toISOString()}`,
          });
        } else {
          throw new RpcException({
            code: status.PERMISSION_DENIED,
            message: `Invalid seed phrase. ${maxAttempts - newAttempts} attempts remaining`,
          });
        }
      }
    } catch (error) {
      this.logger.error(
        `Seed phrase verify error: ${(error as Error).message}`,
      );

      if (error instanceof RpcException) {
        throw error;
      }

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to verify seed phrase',
      });
    }
  }

  async disableSeedPhrase(
    data: DisableSeedPhraseRequest,
  ): Promise<DisableSeedPhraseResponse> {
    try {
      const { userId, seedPhrase } = data;

      // Валидация входных данных
      if (!userId || userId.trim().length === 0 || userId.length > 100) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid user ID',
        });
      }

      if (
        !seedPhrase ||
        seedPhrase.trim().length === 0 ||
        seedPhrase.length > 1000
      ) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid seed phrase',
        });
      }

      // Получаем пользователя
      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new RpcException({
          code: status.NOT_FOUND,
          message: 'User not found',
        });
      }

      if (!user.seedPhraseEnabled || !user.seedPhraseHash) {
        throw new RpcException({
          code: status.FAILED_PRECONDITION,
          message: 'Seed phrase not enabled for this user',
        });
      }

      // Проверяем seed фразу перед отключением
      const isValid = await bcrypt.compare(seedPhrase, user.seedPhraseHash);

      if (!isValid) {
        throw new RpcException({
          code: status.PERMISSION_DENIED,
          message: 'Invalid seed phrase',
        });
      }

      // Отключаем seed фразу
      await this.prismaService.user.update({
        where: { id: userId },
        data: {
          seedPhraseEnabled: false,
          seedPhraseHash: null,
          seedPhraseSalt: null,
          seedPhraseAttempts: 0,
          seedPhraseLockedUntil: null,
        },
      });

      this.logger.log(`🔐 [SEED] Disabled for user ${userId}`);
      return {
        success: true,
        message: 'Seed phrase disabled successfully',
      };
    } catch (error) {
      this.logger.error(
        `Seed phrase disable error: ${(error as Error).message}`,
      );

      if (error instanceof RpcException) {
        throw error;
      }

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to disable seed phrase',
      });
    }
  }

  async getSeedPhraseStatus(
    data: GetSeedPhraseStatusRequest,
  ): Promise<GetSeedPhraseStatusResponse> {
    try {
      const { userId } = data;

      // Валидация входных данных
      if (!userId || userId.trim().length === 0 || userId.length > 100) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid user ID',
        });
      }

      // Получаем пользователя
      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
        select: {
          seedPhraseEnabled: true,
          seedPhraseAttempts: true,
          seedPhraseLockedUntil: true,
        },
      });

      if (!user) {
        throw new RpcException({
          code: status.NOT_FOUND,
          message: 'User not found',
        });
      }

      const lockedUntil = user.seedPhraseLockedUntil
        ? user.seedPhraseLockedUntil.toISOString()
        : '';

      return {
        enabled: user.seedPhraseEnabled,
        attempts: user.seedPhraseAttempts,
        lockedUntil,
        message: user.seedPhraseEnabled
          ? 'Seed phrase is enabled'
          : 'Seed phrase is disabled',
      };
    } catch (error) {
      this.logger.error(
        `Seed phrase status error: ${(error as Error).message}`,
      );

      if (error instanceof RpcException) {
        throw error;
      }

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to get seed phrase status',
      });
    }
  }

  private async generateOracleAccessToken(
    userId: string,
    email: string,
  ): Promise<string> {
    const payload = {
      sub: userId,
      email,
      type: 'oracle_access',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 60 * 60, // 1 час для Oracle доступа
    };

    return await this.jwtService.signAsync(payload, {
      secret: this.configService.getOrThrow<string>('JWT_SUPER_SECRET_WORD'),
    });
  }

  // User profile management methods
  async changePassword(
    data: ChangePasswordRequest,
  ): Promise<ChangePasswordResponse> {
    try {
      const { userId, currentPassword, newPassword } = data;

      // Валидация входных данных
      if (!userId || userId.trim().length === 0 || userId.length > 100) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid user ID',
        });
      }

      if (
        !currentPassword ||
        currentPassword.trim().length === 0 ||
        currentPassword.length > 1000
      ) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid current password',
        });
      }

      if (
        !newPassword ||
        newPassword.trim().length === 0 ||
        newPassword.length > 1000
      ) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid new password',
        });
      }

      // Получаем пользователя
      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new RpcException({
          code: status.NOT_FOUND,
          message: 'User not found',
        });
      }

      // Проверяем текущий пароль
      const isCurrentPasswordValid = await bcrypt.compare(
        currentPassword,
        user.password,
      );
      if (!isCurrentPasswordValid) {
        throw new RpcException({
          code: status.PERMISSION_DENIED,
          message: 'Invalid current password',
        });
      }

      // Проверяем, что новый пароль отличается от текущего
      const isSamePassword = await bcrypt.compare(newPassword, user.password);
      if (isSamePassword) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'New password must be different from current password',
        });
      }

      // Хешируем новый пароль
      const salt = await bcrypt.genSalt(14);
      const hashedNewPassword = await bcrypt.hash(newPassword, salt);

      // Обновляем пароль
      await this.prismaService.user.update({
        where: { id: userId },
        data: {
          password: hashedNewPassword,
          passwordChangedAt: new Date(),
        },
      });

      this.logger.log(`🔐 [PASSWORD] Changed for user ${userId}`);
      return {
        success: true,
        message: 'Password changed successfully',
      };
    } catch (error) {
      this.logger.error(`Password change error: ${(error as Error).message}`);

      if (error instanceof RpcException) {
        throw error;
      }

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to change password',
      });
    }
  }

  async changeEmail(data: ChangeEmailRequest): Promise<ChangeEmailResponse> {
    try {
      const { userId, currentPassword, newEmail } = data;

      // Валидация входных данных
      if (!userId || userId.trim().length === 0 || userId.length > 100) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid user ID',
        });
      }

      if (
        !currentPassword ||
        currentPassword.trim().length === 0 ||
        currentPassword.length > 1000
      ) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid current password',
        });
      }

      if (!newEmail || newEmail.trim().length === 0 || newEmail.length > 255) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid new email',
        });
      }

      // Валидация формата email
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(newEmail)) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid email format',
        });
      }

      // Получаем пользователя
      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new RpcException({
          code: status.NOT_FOUND,
          message: 'User not found',
        });
      }

      // Проверяем текущий пароль
      const isCurrentPasswordValid = await bcrypt.compare(
        currentPassword,
        user.password,
      );
      if (!isCurrentPasswordValid) {
        throw new RpcException({
          code: status.PERMISSION_DENIED,
          message: 'Invalid current password',
        });
      }

      // Проверяем, что новый email отличается от текущего
      if (user.email === newEmail) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'New email must be different from current email',
        });
      }

      // Проверяем, что новый email не занят
      const existingUser = await this.prismaService.user.findUnique({
        where: { email: newEmail },
      });

      if (existingUser) {
        throw new RpcException({
          code: status.ALREADY_EXISTS,
          message: 'Email already exists',
        });
      }

      // Обновляем email
      await this.prismaService.user.update({
        where: { id: userId },
        data: {
          email: newEmail,
          isEmailVerified: false, // Сбрасываем верификацию email
          emailVerificationToken: null,
        },
      });

      this.logger.log(
        `📧 [EMAIL] Changed for user ${userId} from ${user.email} to ${newEmail}`,
      );
      return {
        success: true,
        message:
          'Email changed successfully. Please verify your new email address.',
      };
    } catch (error) {
      this.logger.error(`Email change error: ${(error as Error).message}`);

      if (error instanceof RpcException) {
        throw error;
      }

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to change email',
      });
    }
  }

  async changeTelegramAccount(
    data: ChangeTelegramAccountRequest,
  ): Promise<ChangeTelegramAccountResponse> {
    try {
      const {
        userId,
        telegramId,
        firstName,
        lastName,
        username,
        photoUrl,
        authDate,
        hash,
      } = data;

      // Валидация входных данных
      if (!userId || userId.trim().length === 0 || userId.length > 100) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid user ID',
        });
      }

      if (
        !telegramId ||
        telegramId.trim().length === 0 ||
        telegramId.length > 50
      ) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid telegram ID',
        });
      }

      if (
        !firstName ||
        firstName.trim().length === 0 ||
        firstName.length > 100
      ) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid first name',
        });
      }

      if (!authDate || !hash || authDate.length > 20 || hash.length > 100) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Missing or invalid authentication data',
        });
      }

      // Получаем пользователя
      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new RpcException({
          code: status.NOT_FOUND,
          message: 'User not found',
        });
      }

      // Проверяем, что новый Telegram ID не занят другим пользователем
      if (user.telegramId !== telegramId) {
        const existingTelegramUser = await this.prismaService.user.findUnique({
          where: { telegramId },
        });

        if (existingTelegramUser && existingTelegramUser.id !== userId) {
          throw new RpcException({
            code: status.ALREADY_EXISTS,
            message: 'This Telegram account is already linked to another user',
          });
        }
      }

      // Генерируем Oracle username на основе Telegram данных
      const oracleUsername = this.oracleUsernameService.generateOracleUsername(
        telegramId,
        username,
      );

      // Проверяем, что новый Oracle username не занят другим пользователем
      const existingOracleUser = await this.prismaService.user.findUnique({
        where: { oracleUsername: oracleUsername },
      });

      if (existingOracleUser && existingOracleUser.id !== userId) {
        throw new RpcException({
          code: status.ALREADY_EXISTS,
          message: 'Oracle username is already taken by another user',
        });
      }

      // Обновляем Telegram данные
      await this.prismaService.user.update({
        where: { id: userId },
        data: {
          telegramId: telegramId,
          telegramUsername: username,
          telegramFirstName: firstName,
          telegramLastName: lastName,
          telegramPhotoUrl: photoUrl,
          isTelegramVerified: true,
          oracleUsername: oracleUsername, // Автоматически синхронизируем Oracle username
        },
      });

      this.logger.log(
        `📱 [TELEGRAM] Account changed for user ${userId} to ${telegramId}`,
      );
      return {
        success: true,
        message: 'Telegram account changed successfully',
      };
    } catch (error) {
      this.logger.error(
        `Telegram account change error: ${(error as Error).message}`,
      );

      if (error instanceof RpcException) {
        throw error;
      }

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to change Telegram account',
      });
    }
  }

  async terminateAllSessions(
    data: TerminateAllSessionsRequest,
  ): Promise<TerminateAllSessionsResponse> {
    try {
      const { userId } = data;

      // Валидация входных данных
      if (!userId || userId.trim().length === 0 || userId.length > 100) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid user ID',
        });
      }

      // Получаем пользователя
      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new RpcException({
          code: status.NOT_FOUND,
          message: 'User not found',
        });
      }

      // Получаем количество активных сессий
      const activeSessions = await this.prismaService.session.findMany({
        where: {
          userId: userId,
          isActive: true,
        },
      });

      const terminatedCount = activeSessions.length;

      // Деактивируем все сессии
      await this.prismaService.session.updateMany({
        where: {
          userId: userId,
          isActive: true,
        },
        data: {
          isActive: false,
        },
      });

      this.logger.log(
        `🔒 [SESSIONS] Terminated ${terminatedCount} sessions for user ${userId}`,
      );
      return {
        success: true,
        message: `Successfully terminated ${terminatedCount} active sessions`,
        terminatedSessions: terminatedCount,
      };
    } catch (error) {
      this.logger.error(
        `Terminate sessions error: ${(error as Error).message}`,
      );

      if (error instanceof RpcException) {
        throw error;
      }

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to terminate sessions',
      });
    }
  }

  async linkEmailToAccount(data: LinkEmailRequest): Promise<LinkEmailResponse> {
    const { userId, email, password } = data;

    this.logger.log(`📧 [EMAIL] LINK request received for user ${userId}`);

    try {
      // 1. Валидация входных данных
      if (!userId || userId.trim().length === 0 || userId.length > 100) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid user ID',
        });
      }

      if (!email || email.trim().length === 0 || email.length > 255) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid email address',
        });
      }

      if (!password || password.trim().length === 0 || password.length > 1000) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid password',
        });
      }

      // 2. Проверяем формат email
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid email format',
        });
      }

      // 3. Получаем пользователя
      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new RpcException({
          code: status.NOT_FOUND,
          message: 'User not found',
        });
      }

      // 4. Проверяем, что у пользователя еще нет реального email
      if (user.email && !user.email.startsWith('tg_')) {
        throw new RpcException({
          code: status.ALREADY_EXISTS,
          message: 'User already has a real email address linked',
        });
      }

      // 5. Проверяем, что новый email не занят другим пользователем
      const existingEmailUser = await this.prismaService.user.findUnique({
        where: { email: email.toLowerCase() },
      });

      if (existingEmailUser && existingEmailUser.id !== userId) {
        throw new RpcException({
          code: status.ALREADY_EXISTS,
          message: 'Email address is already in use',
        });
      }

      // 6. Хешируем пароль
      const saltRounds = 12;
      const hashedPassword = await bcrypt.hash(password, saltRounds);

      // 7. Обновляем пользователя с новым email и паролем
      await this.prismaService.user.update({
        where: { id: userId },
        data: {
          email: email.toLowerCase(),
          password: hashedPassword,
          passwordChangedAt: new Date(),
          isEmailVerified: false, // Требует верификации
          emailVerificationToken: crypto.randomBytes(32).toString('hex'),
        },
      });

      this.logger.log(
        `✅ [EMAIL] Successfully linked email ${email} to user ${userId}`,
      );

      return {
        success: true,
        message:
          'Email successfully linked to account. Please verify your email address.',
      };
    } catch (error) {
      this.logger.error(`Email link error: ${(error as Error).message}`);

      if (error instanceof RpcException) {
        throw error;
      }

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to link email to account',
      });
    }
  }

  async syncOracleUsername(
    data: SyncOracleUsernameRequest,
  ): Promise<SyncOracleUsernameResponse> {
    const { userId } = data;

    this.logger.log(`🔄 [ORACLE] SYNC request received for user ${userId}`);

    try {
      // 1. Валидация входных данных
      if (!userId || userId.trim().length === 0 || userId.length > 100) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid user ID',
        });
      }

      // 2. Получаем пользователя
      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new RpcException({
          code: status.NOT_FOUND,
          message: 'User not found',
        });
      }

      // 3. Проверяем, что у пользователя привязан Telegram
      if (!user.telegramId) {
        throw new RpcException({
          code: status.FAILED_PRECONDITION,
          message:
            'Telegram account is not linked. Cannot sync Oracle username.',
        });
      }

      // 4. Генерируем новый Oracle username на основе текущих Telegram данных
      const newOracleUsername =
        this.oracleUsernameService.generateOracleUsername(
          user.telegramId,
          user.telegramUsername || undefined,
        );

      // 5. Проверяем, что новый username не занят другим пользователем
      if (newOracleUsername !== user.oracleUsername) {
        const existingUser = await this.prismaService.user.findUnique({
          where: { oracleUsername: newOracleUsername },
        });

        if (existingUser && existingUser.id !== userId) {
          // Генерируем альтернативные username
          const alternatives =
            await this.oracleIdentityService.generateUsernameAlternatives(
              newOracleUsername,
              userId,
              5,
            );

          throw new RpcException({
            code: status.ALREADY_EXISTS,
            message: 'Oracle username is already taken by another user',
            details: JSON.stringify({
              hasAlternatives: alternatives.length > 0,
              alternativeUsernames: alternatives,
            }),
          });
        }
      }

      // 6. Обновляем Oracle username
      await this.prismaService.user.update({
        where: { id: userId },
        data: {
          oracleUsername: newOracleUsername,
        },
      });

      this.logger.log(
        `✅ [ORACLE] Successfully synced Oracle username to ${newOracleUsername} for user ${userId}`,
      );

      return {
        success: true,
        message: 'Oracle username synchronized successfully',
        oracleUsername: newOracleUsername,
      };
    } catch (error) {
      this.logger.error(
        `Oracle username sync error: ${(error as Error).message}`,
      );

      if (error instanceof RpcException) {
        throw error;
      }

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to sync Oracle username',
      });
    }
  }

  // Oracle identity management methods
  async changeOracleUsername(
    data: ChangeOracleUsernameRequest,
  ): Promise<ChangeOracleUsernameResponse> {
    try {
      const { userId, newUsername } = data;

      this.logger.log(`🔄 [ORACLE] Username change request for user ${userId}`);

      // Проверяем, может ли пользователь изменить Oracle Username
      const canChange =
        await this.oracleIdentityService.canChangeOracleUsername(userId);
      if (!canChange.canChange) {
        throw new RpcException({
          code: status.FAILED_PRECONDITION,
          message: canChange.reason || 'Cannot change Oracle username',
        });
      }

      const updatedUsername =
        await this.oracleIdentityService.changeOracleUsername(
          userId,
          newUsername,
        );

      return {
        success: true,
        message: 'Oracle username changed successfully',
        oracleUsername: updatedUsername,
        hasAlternatives: false,
        alternativeUsernames: [],
      };
    } catch (error) {
      this.logger.error(
        `Oracle username change error: ${(error as Error).message}`,
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

  async changeOracleNickName(
    data: ChangeOracleNickNameRequest,
  ): Promise<ChangeOracleNickNameResponse> {
    try {
      const { userId, newNickname } = data;

      this.logger.log(`🔄 [ORACLE] NickName change request for user ${userId}`);

      const updatedNickName =
        await this.oracleIdentityService.changeOracleNickName(
          userId,
          newNickname,
        );

      return {
        success: true,
        message: 'Oracle nickname changed successfully',
        oracleNickname: updatedNickName,
      };
    } catch (error) {
      this.logger.error(
        `Oracle nickname change error: ${(error as Error).message}`,
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

  async getOracleIdentity(
    data: GetOracleIdentityRequest,
  ): Promise<GetOracleIdentityResponse> {
    try {
      const { userId } = data;

      this.logger.log(`🔄 [ORACLE] Identity request for user ${userId}`);

      const identity =
        await this.oracleIdentityService.getOracleIdentity(userId);

      return {
        success: true,
        message: 'Oracle identity retrieved successfully',
        userId: identity.userId,
        oracleUsername: identity.oracleUsername || '',
        oracleNickname: identity.oracleNickName || '',
      };
    } catch (error) {
      this.logger.error(
        `Oracle identity retrieval error: ${(error as Error).message}`,
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

  async suggestUsernameAlternatives(
    data: SuggestOracleUsernameAlternativesRequest,
  ): Promise<SuggestOracleUsernameAlternativesResponse> {
    try {
      const { userId, desiredUsername, maxAlternatives } = data;

      this.logger.log(
        `🔄 [ORACLE] Username alternatives request for user ${userId}, desired: ${desiredUsername}`,
      );

      const alternatives =
        await this.oracleIdentityService.suggestUsernameAlternatives(
          userId,
          desiredUsername,
          maxAlternatives || 5,
        );

      return {
        success: true,
        message: `Generated ${alternatives.length} alternative usernames`,
        alternativeUsernames: alternatives,
      };
    } catch (error) {
      this.logger.error(
        `Username alternatives suggestion error: ${(error as Error).message}`,
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
