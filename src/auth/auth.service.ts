import { Injectable, Logger } from '@nestjs/common';
import { BCRYPT_COST } from '../common/constants';
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
  SyncUsernameRequest,
  SyncUsernameResponse,
  ChangeUsernameRequest,
  ChangeUsernameResponse,
  ChangeNicknameRequest,
  ChangeNicknameResponse,
  ChangeTelegramUsernameRequest,
  ChangeTelegramUsernameResponse,
  ChangeAvatarRequest,
  ChangeAvatarResponse,
  GetUserIdentityRequest,
  GetUserIdentityResponse,
  GetUserProfileRequest,
  GetUserProfileResponse,
  SuggestUsernameAlternativesRequest,
  SuggestUsernameAlternativesResponse,
} from './auth';
import { PrismaService } from '../prisma.service';
import { JwtService } from '@nestjs/jwt';
import { RpcException } from '@nestjs/microservices';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { status } from '@grpc/grpc-js';
import { EncryptionService } from '../security/services/encryption.service';
import { EnhancedJwtService } from '../security/services/enhanced-jwt.service';
import { SessionService } from '../security/services/session.service';
import { UsernameService } from './services/username.service';
import { UserIdentityService } from './services/user-identity.service';
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
    private readonly usernameService: UsernameService,
    private readonly userIdentityService: UserIdentityService,
    private readonly enhancedJwtService: EnhancedJwtService,
    private readonly sessionService: SessionService,
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
      const { email, password, username } = data;

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

      // Username обязателен: нормализуем, валидируем, резолвим уникальность.
      if (!username || username.trim().length === 0) {
        const error: GrpcError = {
          code: status.INVALID_ARGUMENT,
          message: 'Username is required',
        };
        throw new RpcException(error);
      }
      const normalizedUsername = this.usernameService.normalizeUserUsername(username);
      if (!this.usernameService.isValidUserUsername(normalizedUsername)) {
        const error: GrpcError = {
          code: status.INVALID_ARGUMENT,
          message:
            'Username may only contain letters, digits, underscores and hyphens (max 50 chars)',
        };
        throw new RpcException(error);
      }
      const resolvedUsername = await this.resolveUniqueUserUsername(
        normalizedUsername,
        '', // новый пользователь — userId ещё нет
      );

      const salt = await bcrypt.genSalt(BCRYPT_COST);
      const hashedPassword = await bcrypt.hash(password, salt);

      const newUser = await this.prismaService.user.create({
        data: {
          email,
          password: hashedPassword,
          username: resolvedUsername,
        },
      });

      const tokens = await this.enhancedJwtService.generateTokens(
        newUser.id,
        newUser.email,
      );
      return {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
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

      return {
        accessToken,
        refreshToken,
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
      const payload: { sub: string; type?: string; jti?: string } =
        await this.jwtService.verifyAsync(refreshToken, {
          secret: this.configService.getOrThrow<string>('JWT_SECRET'),
        });

      // Проверяем тип токена
      if (payload.type && payload.type !== 'refresh') {
        const error: GrpcError = {
          code: status.PERMISSION_DENIED,
          message: 'Invalid token type for refresh',
        };
        throw new RpcException(error);
      }

      // Проверяем активную сессию по jti refresh-токена (refresh rotation /
      // reuse detection). Если сессия отсутствует или деактивирована — токен
      // считается переиспользованным/недействительным.
      if (!payload.jti) {
        const error: GrpcError = {
          code: status.PERMISSION_DENIED,
          message: 'Invalid refresh token',
        };
        throw new RpcException(error);
      }

      const session = await this.sessionService.findByRefreshJti(payload.jti);
      if (!session || !session.isActive || session.expiresAt < new Date()) {
        const error: GrpcError = {
          code: status.PERMISSION_DENIED,
          message: 'Invalid refresh token',
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

      // Ротация: деактивируем текущую сессию и выпускаем новую пару,
      // которая создаёт новую сессию. Повтор старого refresh теперь отклоняется.
      await this.sessionService.deactivate(session.id);

      const tokens = await this.enhancedJwtService.generateTokens(
        user.id,
        user.email || user.telegramAuth || '',
      );
      return {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
      };
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
      const hash = await bcrypt.hash(seedPhrase, BCRYPT_COST);

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

        // Recovery — security change: отзываем все активные сессии,
        // чтобы старые refresh-токены перестали действовать.
        await this.sessionService.deactivateAll(userId);

        // Recovery flow (§6.3): создаём запрос на восстановление в статусе
        // pending_review и начинаем grace period. Полный доступ выдаётся только
        // после административного подтверждения в виде ограниченного recovery grant.
        const recoveryRequest = await this.prismaService.recoveryRequest.create({
          data: {
            userId,
            status: 'pending_review',
          },
        });

        this.logger.log(
          `🔐 [SEED] Verified for user ${userId}, recovery request ${recoveryRequest.id}`,
        );
        return {
          success: true,
          message:
            'Recovery phrase verified. Request created, pending administrative review.',
          requestId: recoveryRequest.id,
          grantState: 'pending_review',
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
      const salt = await bcrypt.genSalt(BCRYPT_COST);
      const hashedNewPassword = await bcrypt.hash(newPassword, salt);

      // Обновляем пароль
      await this.prismaService.user.update({
        where: { id: userId },
        data: {
          password: hashedNewPassword,
          passwordChangedAt: new Date(),
        },
      });

      // Смена пароля — security change: отзываем все активные сессии,
      // чтобы старые refresh-токены перестали действовать.
      await this.sessionService.deactivateAll(userId);

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

      // Аккаунт, зарегистрированный по email: привязываем только telegram username (ник).
      // Подпись данных виджета уже проверена в контроллере; сохраняем только реальный ник.
      // Если ник занят другим пользователем — приоритет у виджета: снимаем дубль.
      if (user.origin === 'email') {
        const cleanUsername = (username || '').trim().replace(/^@/, '');
        const telegramRegex = /^[a-zA-Z0-9_]{3,32}$/;
        if (!cleanUsername || !telegramRegex.test(cleanUsername)) {
          throw new RpcException({
            code: status.INVALID_ARGUMENT,
            message: 'Invalid telegram username',
          });
        }

        // Аудит смены ника текущего пользователя
        if ((user.telegramUsername || '') !== cleanUsername) {
          await this.prismaService.telegramIdentityAudit.create({
            data: {
              userId,
              eventType: 'telegram_username_linked',
              previousData: {
                telegramUsername: user.telegramUsername,
                changedAt: new Date().toISOString(),
              },
            },
          });
        }

        // Если ник занят другим пользователем — приоритет у виджета, снимаем дубль
        const duplicateUser = await this.prismaService.user.findFirst({
          where: { telegramUsername: cleanUsername, id: { not: userId } },
        });
        if (duplicateUser) {
          await this.prismaService.telegramIdentityAudit.create({
            data: {
              userId: duplicateUser.id,
              eventType: 'telegram_username_removed',
              previousData: {
                telegramUsername: duplicateUser.telegramUsername,
                changedAt: new Date().toISOString(),
              },
            },
          });
          await this.prismaService.user.update({
            where: { id: duplicateUser.id },
            data: { telegramUsername: null },
          });
        }

        await this.prismaService.user.update({
          where: { id: userId },
          data: { telegramUsername: cleanUsername },
        });

        this.logger.log(
          `✅ [TELEGRAM] Linked telegram username ${cleanUsername} to email user ${userId}`,
        );

        return {
          success: true,
          message: 'Telegram username linked successfully',
        };
      }

      // Аудит смены Telegram: логируем старые данные в JSON. Логируется любое
      // изменение identity (telegramId, username/nick, имя, фото), а не только смена id.
      const identityChanged =
        user.telegramId !== telegramId ||
        (user.telegramUsername || '') !== (username || '') ||
        (user.telegramFirstName || '') !== (firstName || '') ||
        (user.telegramLastName || '') !== (lastName || '') ||
        (user.telegramPhotoUrl || '') !== (photoUrl || '');

      if (identityChanged) {
        await this.prismaService.telegramIdentityAudit.create({
          data: {
            userId,
            eventType:
              user.telegramId !== telegramId
                ? 'telegram_changed'
                : 'telegram_identity_updated',
            previousData: {
              telegramId: user.telegramId,
              telegramUsername: user.telegramUsername,
              telegramFirstName: user.telegramFirstName,
              telegramLastName: user.telegramLastName,
              telegramPhotoUrl: user.telegramPhotoUrl,
              isTelegramVerified: user.isTelegramVerified,
              changedAt: new Date().toISOString(),
            },
          },
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

      // Генерируем User username на основе Telegram данных
      const baseUserUsername =
        this.usernameService.generateUsername(
          telegramId,
          username,
        );

      // Резолвим уникальный User username (стабильный fallback при конфликте)
      const resolvedUsername = await this.resolveUniqueUserUsername(
        baseUserUsername,
        userId,
      );

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
          username: resolvedUsername, // Автоматически синхронизируем User username
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
      if (user.origin === 'email') {
        throw new RpcException({
          code: status.ALREADY_EXISTS,
          message: 'User already has a real email address linked',
        });
      }

      // 5-7. Атомарная операция linking (проверка уникальности + запись в одной
      // транзакции, приоритет linking над фоновой sync — §5.1). При конкурентном
      // занятии email уникальный индекс даёт P2002 -> ALREADY_EXISTS.
      await this.prismaService.$transaction(async (tx) => {
        const existingEmailUser = await tx.user.findUnique({
          where: { email: email.toLowerCase() },
        });

        if (existingEmailUser && existingEmailUser.id !== userId) {
          throw new RpcException({
            code: status.ALREADY_EXISTS,
            message: 'Email address is already in use',
          });
        }

        const saltRounds = BCRYPT_COST;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        await tx.user.update({
          where: { id: userId },
          data: {
            email: email.toLowerCase(),
            password: hashedPassword,
            passwordChangedAt: new Date(),
            isEmailVerified: false, // Требует верификации
            emailVerificationToken: crypto.randomBytes(32).toString('hex'),
            origin: 'email', // Аккаунт получил email-identity
          },
        });
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

  async syncUsername(
    data: SyncUsernameRequest,
  ): Promise<SyncUsernameResponse> {
    const { userId } = data;

    this.logger.log(`🔄 [USER] SYNC request received for user ${userId}`);

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
            'Telegram account is not linked. Cannot sync User username.',
        });
      }

      // 4. Генерируем новый User username на основе текущих Telegram данных
      const baseUserUsername =
        this.usernameService.generateUsername(
          user.telegramId,
          user.telegramUsername || undefined,
        );

      // 5. Резолвим уникальный User username (стабильный fallback при конфликте)
      const newUserUsername = await this.resolveUniqueUserUsername(
        baseUserUsername,
        userId,
      );

      // 5.1 Резервируем освободившийся username на grace period (§2.3)
      if (
        user.username &&
        user.username !== newUserUsername
      ) {
        await this.usernameService.reserveUsername(
          userId,
          user.username,
        );
      }

      // 6. Обновляем User username
      await this.prismaService.user.update({
        where: { id: userId },
        data: {
          username: newUserUsername,
        },
      });

      this.logger.log(
        `✅ [USER] Successfully synced User username to ${newUserUsername} for user ${userId}`,
      );

      return {
        success: true,
        message: 'User username synchronized successfully',
        username: newUserUsername,
      };
    } catch (error) {
      this.logger.error(
        `User username sync error: ${(error as Error).message}`,
      );

      if (error instanceof RpcException) {
        throw error;
      }

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to sync User username',
      });
    }
  }

  // User identity management methods
  async changeUsername(
    data: ChangeUsernameRequest,
  ): Promise<ChangeUsernameResponse> {
    try {
      const { userId, newUsername } = data;

      this.logger.log(`🔄 [USER] Username change request for user ${userId}`);

      // Проверяем, может ли пользователь изменить User Username
      const canChange =
        await this.userIdentityService.canChangeUsername(userId);
      if (!canChange.canChange) {
        throw new RpcException({
          code: status.FAILED_PRECONDITION,
          message: canChange.reason || 'Cannot change User username',
        });
      }

      const updatedUsername =
        await this.userIdentityService.changeUsername(
          userId,
          newUsername,
        );

      return {
        success: true,
        message: 'User username changed successfully',
        username: updatedUsername,
        hasAlternatives: false,
        alternativeUsernames: [],
      };
    } catch (error) {
      this.logger.error(
        `User username change error: ${(error as Error).message}`,
      );

      if (error instanceof RpcException) {
        throw error;
      }

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to change User username',
      });
    }
  }

  async changeNickname(
    data: ChangeNicknameRequest,
  ): Promise<ChangeNicknameResponse> {
    try {
      const { userId, newNickname } = data;

      this.logger.log(`🔄 [USER] NickName change request for user ${userId}`);

      const updatedNickName =
        await this.userIdentityService.changeNickname(
          userId,
          newNickname,
        );

      return {
        success: true,
        message: 'User nickname changed successfully',
        nickname: updatedNickName,
      };
    } catch (error) {
      this.logger.error(
        `User nickname change error: ${(error as Error).message}`,
      );

      if (error instanceof RpcException) {
        throw error;
      }

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to change User nickname',
      });
    }
  }

  async changeTelegramUsername(
    data: ChangeTelegramUsernameRequest,
  ): Promise<ChangeTelegramUsernameResponse> {
    try {
      const { userId, telegramUsername } = data;

      this.logger.log(
        `🔄 [USER] Telegram username change request for user ${userId}`,
      );

      const updated =
        await this.userIdentityService.changeTelegramUsername(
          userId,
          telegramUsername,
        );

      return {
        success: true,
        message: 'User telegram username changed successfully',
        telegramUsername: updated,
      };
    } catch (error) {
      this.logger.error(
        `User telegram username change error: ${(error as Error).message}`,
      );

      if (error instanceof RpcException) {
        throw error;
      }

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to change User telegram username',
      });
    }
  }

  async changeAvatar(
    data: ChangeAvatarRequest,
  ): Promise<ChangeAvatarResponse> {
    try {
      const { userId, photoBase64 } = data;

      this.logger.log(`🔄 [USER] Avatar change request for user ${userId}`);

      await this.userIdentityService.changeAvatar(userId, photoBase64);

      return {
        success: true,
        message: 'User avatar changed successfully',
      };
    } catch (error) {
      this.logger.error(
        `User avatar change error: ${(error as Error).message}`,
      );

      if (error instanceof RpcException) {
        throw error;
      }

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to change User avatar',
      });
    }
  }

  async getUserIdentity(
    data: GetUserIdentityRequest,
  ): Promise<GetUserIdentityResponse> {
    try {
      const { userId } = data;

      this.logger.log(`🔄 [USER] Identity request for user ${userId}`);

      const identity =
        await this.userIdentityService.getUserIdentity(userId);

      return {
        success: true,
        message: 'User identity retrieved successfully',
        userId: identity.userId,
        username: identity.username || '',
        nickname: identity.nickname || '',
      };
    } catch (error) {
      this.logger.error(
        `User identity retrieval error: ${(error as Error).message}`,
      );

      if (error instanceof RpcException) {
        throw error;
      }

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to get User identity',
      });
    }
  }

  async getUserProfile(
    data: GetUserProfileRequest,
  ): Promise<GetUserProfileResponse> {
    try {
      const { userId } = data;

      this.logger.log(`🔄 [USER] Profile request for user ${userId}`);

      const profile = await this.userIdentityService.getUserProfile(userId);

      return {
        success: true,
        message: 'User profile retrieved successfully',
        userId: profile.userId,
        email: profile.email,
        username: profile.username,
        nickname: profile.nickname,
        photoBase64: profile.photoBase64,
        telegramUsername: profile.telegramUsername,
        telegramId: profile.telegramId,
        telegramPhotoUrl: profile.telegramPhotoUrl,
        origin: profile.origin,
        isTelegramVerified: profile.isTelegramVerified,
      };
    } catch (error) {
      this.logger.error(
        `User profile retrieval error: ${(error as Error).message}`,
      );

      if (error instanceof RpcException) {
        throw error;
      }

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to get User profile',
      });
    }
  }

  async suggestUsernameAlternatives(
    data: SuggestUsernameAlternativesRequest,
  ): Promise<SuggestUsernameAlternativesResponse> {
    try {
      const { userId, desiredUsername, maxAlternatives } = data;

      this.logger.log(
        `🔄 [USER] Username alternatives request for user ${userId}, desired: ${desiredUsername}`,
      );

      const alternatives =
        await this.userIdentityService.suggestUsernameAlternatives(
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

  /**
   * Возвращает свободный User username для заданного User ID:
   * - точное имя, если свободно или уже принадлежит этому пользователю;
   * - иначе стабильный детерминированный fallback `<username>_<короткий суффикс User ID>`.
   * Конфликт имени не ломает login/linking (TG-03). Имя, активное в grace period
   * за другим User ID, считается недоступным (§2.3).
   */
  private async resolveUniqueUserUsername(
    baseUsername: string,
    userId: string,
  ): Promise<string> {
    const existing = await this.prismaService.user.findUnique({
      where: { username: baseUsername },
    });
    if (!existing || existing.id === userId) {
      const reserved = await this.usernameService.isUsernameReservedByOther(
        baseUsername,
        userId,
      );
      if (reserved) {
        const idDigits = userId.replace(/-/g, '');
        return this.usernameService.generateAlternativeUsername(
          baseUsername,
          idDigits.slice(0, 4).toLowerCase(),
        );
      }
      return baseUsername;
    }

    const idDigits = userId.replace(/-/g, '');
    const suffix = idDigits.slice(0, 4).toLowerCase();
    const fallback = this.usernameService.generateAlternativeUsername(
      baseUsername,
      suffix,
    );

    const existingFallback = await this.prismaService.user.findUnique({
      where: { username: fallback },
    });
    if (!existingFallback || existingFallback.id === userId) {
      return fallback;
    }

    const fallback2 =
      this.usernameService.generateAlternativeUsername(
        baseUsername,
        idDigits.slice(0, 8).toLowerCase(),
      );
    return fallback2;
  }

  /**
   * Решение администратора по recovery-запросу (§6.3). При approved запрос
   * переводится в granted и выдаётся ограниченный recovery grant с TTL.
   */
  async resolveRecoveryRequest(
    requestId: string,
    decision: 'approved' | 'rejected' | 'cancelled' | 'needs_review',
    decidedBy: string,
    reason?: string,
  ): Promise<{
    success: boolean;
    status: string;
    grantToken?: string;
    message: string;
  }> {
    const request = await this.prismaService.recoveryRequest.findUnique({
      where: { id: requestId },
    });
    if (!request) {
      throw new RpcException({
        code: status.NOT_FOUND,
        message: 'Recovery request not found',
      });
    }

    if (decision === 'approved') {
      const grantTtlSeconds = this.configService.get<number>(
        'RECOVERY_GRANT_TTL_SECONDS',
        24 * 60 * 60,
      );
      const grantExpiresAt = new Date(
        Date.now() + grantTtlSeconds * 1000,
      );

      await this.prismaService.recoveryRequest.update({
        where: { id: requestId },
        data: {
          status: 'granted',
          decidedBy,
          decidedAt: new Date(),
          reason,
          grantExpiresAt,
        },
      });

      const grantToken = await this.jwtService.signAsync(
        {
          sub: request.userId,
          typ: 'recovery_grant',
          rid: requestId,
        },
        { expiresIn: grantTtlSeconds },
      );

      return {
        success: true,
        status: 'granted',
        grantToken,
        message: 'Recovery grant issued',
      };
    }

    await this.prismaService.recoveryRequest.update({
      where: { id: requestId },
      data: {
        status: decision,
        decidedBy,
        decidedAt: new Date(),
        reason: reason ?? null,
      },
    });

    return {
      success: true,
      status: decision,
      message: `Recovery request ${decision}`,
    };
  }
}
