import { Controller, Logger } from '@nestjs/common';
import { GrpcMethod } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import { TelegramAuthService } from './telegram-auth.service';
import {
  LoginRequest,
  LoginResponse,
  RegisterRequest,
  RegisterResponse,
  RefreshTokenRequest,
  RefreshTokenResponse,
  TelegramAuthRequest,
  TelegramAuthResponse,
  TelegramLoginRequest,
  TelegramLoginResponse,
  LinkTelegramRequest,
  LinkTelegramResponse,
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
import { SecurityLoggerService } from '../security/security-logger.service';
import { BruteForceService } from '../security/services/brute-force.service';
import { SecureAuthService } from '../security/services/secure-auth.service';
import { EnhancedJwtService } from '../security/services/enhanced-jwt.service';
import { TwoFactorAuthService } from '../security/services/two-factor-auth.service';
import { AnomalyDetectionService } from '../security/services/anomaly-detection.service';
import { EncryptionService } from '../security/services/encryption.service';
import { OracleUsernameService } from './services/oracle-username.service';
import { OracleIdentityService } from './services/oracle-identity.service';
import { PrismaService } from '../prisma.service';
import { RpcException } from '@nestjs/microservices';
import { status } from '@grpc/grpc-js';
import { Throttle } from '@nestjs/throttler';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';

// node test-grpc-client.js

@Controller()
export class AuthController {
  private readonly logger = new Logger(AuthController.name);
  constructor(
    private readonly authService: AuthService,
    private readonly telegramAuthService: TelegramAuthService,
    private readonly securityLogger: SecurityLoggerService,
    private readonly bruteForceService: BruteForceService,
    private readonly secureAuthService: SecureAuthService,
    private readonly enhancedJwtService: EnhancedJwtService,
    private readonly twoFactorAuthService: TwoFactorAuthService,
    private readonly anomalyDetectionService: AnomalyDetectionService,
    private readonly encryptionService: EncryptionService,
    private readonly oracleUsernameService: OracleUsernameService,
    private readonly oracleIdentityService: OracleIdentityService,
    private readonly prismaService: PrismaService,
  ) {}

  @GrpcMethod('AuthService', 'login')
  async login(data: LoginRequest, metadata: any): Promise<LoginResponse> {
    const { email, password } = data;
    const ipAddress =
      metadata.get('x-forwarded-for')?.[0] ||
      metadata.get('x-real-ip')?.[0] ||
      'unknown';
    const userAgent = metadata.get('user-agent')?.[0] || 'unknown';

    this.logger.log(`🔐 [AUTH] LOGIN request received for email: ${email}`);

    try {
      // 1. Валидация формата email
      const emailRegex =
        /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
      if (!emailRegex.test(email)) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid email format',
        });
      }

      // 2. Проверяем brute force блокировку
      const isBlocked = await this.bruteForceService.isBlocked(email);
      if (isBlocked) {
        await this.securityLogger.logAuthAttempt('gRPC', email, false);
        throw new RpcException({
          code: status.RESOURCE_EXHAUSTED,
          message: 'Too many failed attempts. Please try again later.',
        });
      }

      // 2. Безопасная аутентификация
      const authResult: {
        success: boolean;
        user?: { id: string; email: string };
      } = await this.secureAuthService.authenticateUser(email, password);

      if (!authResult.success || !authResult.user) {
        // Записываем неудачную попытку
        await this.bruteForceService.recordFailedAttempt(email);
        await this.securityLogger.logAuthAttempt('gRPC', email, false);
        throw new Error('Invalid credentials');
      }

      // 3. Анализ аномалий поведения
      const behavior: {
        userId: string;
        ipAddress: string;
        userAgent: string;
        action: string;
        success: boolean;
        timestamp: Date;
      } = {
        userId: authResult.user.id,
        ipAddress: ipAddress,
        userAgent: userAgent,
        action: 'login',
        success: true,
        timestamp: new Date(),
      };

      const anomalyScore: { score: number } =
        (await this.anomalyDetectionService.analyzeUserBehavior(
          authResult.user.id,
          behavior,
        )) as { score: number };

      if (anomalyScore.score > 0.7) {
        this.securityLogger.logAnomaly('gRPC', email, anomalyScore);
        // Можно добавить дополнительную проверку или блокировку
      }

      // 4. Генерируем токены с JTI и шифрованием
      const tokens = await this.enhancedJwtService.generateTokens(
        authResult.user.id,
        authResult.user.email,
      );

      // 5. Шифруем чувствительные данные в токенах
      const encryptedAccessToken = this.encryptionService.encrypt(
        tokens.accessToken,
      );
      const encryptedRefreshToken = this.encryptionService.encrypt(
        tokens.refreshToken,
      );

      // 6. Проверяем 2FA статус пользователя
      const user = await this.prismaService.user.findUnique({
        where: { email },
      });
      if (user && user.twoFactorEnabled) {
        // Если 2FA включен, возвращаем специальный токен для 2FA проверки
        this.securityLogger.logJwtEvent(
          '2FA_REQUIRED',
          `User ${email} requires 2FA verification`,
        );
        return {
          accessToken: '2FA_REQUIRED',
          refreshToken: '2FA_REQUIRED',
        };
      }

      // 7. Очищаем счетчик неудачных попыток
      await this.bruteForceService.clearFailedAttempts(email);

      await this.securityLogger.logAuthAttempt('gRPC', email, true);
      return {
        accessToken: encryptedAccessToken,
        refreshToken: encryptedRefreshToken,
      };
    } catch (error) {
      await this.securityLogger.logAuthAttempt('gRPC', email, false);

      // Безопасная обработка ошибок
      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(`Login error: ${(error as Error).message}`);

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Authentication failed',
      });
    }
  }

  @GrpcMethod('AuthService', 'register')
  @Throttle({ default: { ttl: 300000, limit: 3 } }) // 3 регистрации в 5 минут
  async register(data: RegisterRequest): Promise<RegisterResponse> {
    const { email, password } = data;

    this.logger.log(`📝 [AUTH] REGISTER request received for email: ${email}`);

    try {
      // 1. Валидация входных данных
      if (!email || email.trim().length === 0 || email.length > 255) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid email address',
        });
      }

      // Валидация формата email
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid email format',
        });
      }

      if (!password || password.trim().length === 0 || password.length > 1000) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid password',
        });
      }

      // 2. Проверяем сложность пароля
      const passwordValidation =
        this.secureAuthService.validatePasswordStrength(password);
      if (!passwordValidation.valid) {
        await this.securityLogger.logRegistration('gRPC', email, false);
        throw new Error(
          `Password validation failed: ${passwordValidation.errors.join(', ')}`,
        );
      }

      // 2. Регистрируем пользователя
      const tokens = await this.authService.register(data);

      // 3. Шифруем токены для консистентности
      const encryptedAccessToken = this.encryptionService.encrypt(
        tokens.accessToken,
      );
      const encryptedRefreshToken = this.encryptionService.encrypt(
        tokens.refreshToken,
      );

      await this.securityLogger.logRegistration('gRPC', email, true);
      return {
        accessToken: encryptedAccessToken,
        refreshToken: encryptedRefreshToken,
      };
    } catch (error) {
      await this.securityLogger.logRegistration('gRPC', email, false);

      // Безопасная обработка ошибок
      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(`Registration error: ${(error as Error).message}`);

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Registration failed',
      });
    }
  }

  @GrpcMethod('AuthService', 'refreshToken')
  async refreshToken(data: RefreshTokenRequest): Promise<RefreshTokenResponse> {
    this.logger.log(`🔄 [AUTH] REFRESH_TOKEN request received`);

    try {
      // 1. Валидация входных данных
      if (
        !data.refreshToken ||
        data.refreshToken.trim().length === 0 ||
        data.refreshToken.length > 2000
      ) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid refresh token',
        });
      }

      const tokens = await this.authService.refreshToken(data.refreshToken);

      // Шифруем токены для консистентности
      const encryptedAccessToken = this.encryptionService.encrypt(
        tokens.accessToken,
      );
      const encryptedRefreshToken = this.encryptionService.encrypt(
        tokens.refreshToken,
      );

      await this.securityLogger.logTokenRefresh('gRPC', true);
      return {
        accessToken: encryptedAccessToken,
        refreshToken: encryptedRefreshToken,
      };
    } catch (error) {
      await this.securityLogger.logTokenRefresh('gRPC', false);

      // Безопасная обработка ошибок
      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(`Token refresh error: ${(error as Error).message}`);

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Token refresh failed',
      });
    }
  }

  @GrpcMethod('AuthService', 'enable2FA')
  async enable2FA(data: {
    userId: string;
  }): Promise<{ qrCode: string; backupCodes: string[] }> {
    this.logger.log(`🔐 [2FA] ENABLE request received for user ${data.userId}`);

    try {
      // 1. Валидация входных данных
      if (
        !data.userId ||
        data.userId.trim().length === 0 ||
        data.userId.length > 100
      ) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid user ID',
        });
      }

      const result = await this.twoFactorAuthService.enable2FA(data.userId, '');
      this.securityLogger.logJwtEvent(
        '2FA_ENABLED',
        `User ${data.userId} enabled 2FA`,
      );
      return result;
    } catch (error) {
      this.securityLogger.logSecurityError(
        '2FA_ENABLE_FAILED',
        (error as Error).message,
      );

      // Безопасная обработка ошибок
      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(`2FA enable error: ${(error as Error).message}`);

      throw new RpcException({
        code: status.INTERNAL,
        message: '2FA enable failed',
      });
    }
  }

  @GrpcMethod('AuthService', 'verify2FA')
  async verify2FA(data: {
    userId: string;
    token: string;
  }): Promise<{ success: boolean }> {
    this.logger.log(`🔐 [2FA] VERIFY request received for user ${data.userId}`);

    try {
      // 1. Валидация входных данных
      if (
        !data.userId ||
        data.userId.trim().length === 0 ||
        data.userId.length > 100
      ) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid user ID',
        });
      }

      if (
        !data.token ||
        data.token.trim().length === 0 ||
        data.token.length > 10
      ) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid 2FA token',
        });
      }

      const user = await this.prismaService.user.findUnique({
        where: { id: data.userId },
      });
      if (!user || !user.twoFactorSecret) {
        throw new Error('2FA not enabled for this user');
      }

      const isValid = this.twoFactorAuthService.verifyTOTP(
        user.twoFactorSecret,
        data.token,
      );
      this.securityLogger.logJwtEvent(
        '2FA_VERIFIED',
        `User ${data.userId} 2FA verification: ${isValid}`,
      );
      return { success: isValid };
    } catch (error) {
      this.securityLogger.logSecurityError(
        '2FA_VERIFY_FAILED',
        (error as Error).message,
      );

      // Безопасная обработка ошибок
      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(`2FA verify error: ${(error as Error).message}`);

      throw new RpcException({
        code: status.INTERNAL,
        message: '2FA verification failed',
      });
    }
  }

  @GrpcMethod('AuthService', 'getAnomalyStats')
  async getAnomalyStats(data: { userId: string }): Promise<any> {
    this.logger.log(
      `📊 [ANOMALY] STATS request received for user ${data.userId}`,
    );

    try {
      // 1. Валидация входных данных
      if (
        !data.userId ||
        data.userId.trim().length === 0 ||
        data.userId.length > 100
      ) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid user ID',
        });
      }

      const stats = await this.anomalyDetectionService.getAnomalyStats(
        data.userId,
      );
      this.securityLogger.logJwtEvent(
        'ANOMALY_STATS',
        `Retrieved stats for user ${data.userId}`,
      );
      return stats;
    } catch (error) {
      this.securityLogger.logSecurityError(
        'ANOMALY_STATS_FAILED',
        (error as Error).message,
      );
      throw error;
    }
  }

  @GrpcMethod('AuthService', 'telegramAuth')
  @Throttle({ default: { ttl: 60000, limit: 10 } }) // 10 попыток Telegram auth в минуту
  async telegramAuth(
    data: TelegramAuthRequest,
    metadata?: any,
  ): Promise<TelegramAuthResponse> {
    const {
      telegramId,
      firstName,
      lastName,
      username,
      photoUrl,
      authDate,
      hash,
    } = data;

    this.logger.log(
      `📱 [TELEGRAM] AUTH request received for Telegram ID: ${telegramId}`,
    );

    try {
      // 1. Валидация входных данных
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

      if (lastName && lastName.length > 100) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid last name',
        });
      }

      if (username && username.length > 50) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid username',
        });
      }

      if (photoUrl && photoUrl.length > 500) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid photo URL',
        });
      }

      if (!authDate || !hash || authDate.length > 20 || hash.length > 100) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Missing or invalid authentication data',
        });
      }

      // 2. Проверяем brute force блокировку
      const isBlocked = await this.bruteForceService.isBlocked(
        `telegram_${telegramId}`,
      );
      if (isBlocked) {
        await this.securityLogger.logAuthAttempt(
          'gRPC_TELEGRAM',
          `telegram_${telegramId}`,
          false,
        );
        throw new RpcException({
          code: status.RESOURCE_EXHAUSTED,
          message: 'Too many failed attempts. Please try again later.',
        });
      }

      // 3. Валидируем Telegram данные
      const authData = {
        telegramId: telegramId,
        firstName: firstName,
        lastName: lastName,
        username,
        photoUrl: photoUrl,
        authDate: authDate,
        hash,
      };

      const isValid = this.telegramAuthService.validateTelegramAuth(authData);
      if (!isValid) {
        await this.bruteForceService.recordFailedAttempt(
          `telegram_${telegramId}`,
        );
        await this.securityLogger.logAuthAttempt(
          'gRPC_TELEGRAM',
          `telegram_${telegramId}`,
          false,
        );
        throw new RpcException({
          code: status.UNAUTHENTICATED,
          message: 'Invalid Telegram authentication data',
        });
      }

      // 4. Аутентифицируем или создаем пользователя
      const result =
        await this.telegramAuthService.authenticateOrCreateUser(authData);
      const { user, isNewUser } = result;

      // 5. Анализ аномалий поведения (получаем реальные данные из metadata)
      const ipAddress =
        metadata?.get('x-forwarded-for')?.[0] ||
        metadata?.get('x-real-ip')?.[0] ||
        'telegram_oauth';
      const userAgent =
        metadata?.get('user-agent')?.[0] ||
        metadata?.get('x-user-agent')?.[0] ||
        'telegram_bot';

      const behavior: {
        userId: string;
        ipAddress: string;
        userAgent: string;
        action: string;
        success: boolean;
        timestamp: Date;
      } = {
        userId: user.id,
        ipAddress: ipAddress,
        userAgent: userAgent,
        action: 'telegram_auth',
        success: true,
        timestamp: new Date(),
      };

      const anomalyScore: { score: number } =
        (await this.anomalyDetectionService.analyzeUserBehavior(
          user.id,
          behavior,
        )) as { score: number };

      if (anomalyScore.score > 0.7) {
        this.securityLogger.logAnomaly(
          'gRPC_TELEGRAM',
          `telegram_${telegramId}`,
          anomalyScore,
        );
      }

      // 6. Генерируем токены
      const tokens = await this.telegramAuthService.generateTokens(
        user.id,
        user.email,
      );

      // 7. Шифруем токены
      const encryptedAccessToken = this.encryptionService.encrypt(
        tokens.accessToken,
      );
      const encryptedRefreshToken = this.encryptionService.encrypt(
        tokens.refreshToken,
      );

      // 8. Очищаем счетчик неудачных попыток
      await this.bruteForceService.clearFailedAttempts(
        `telegram_${telegramId}`,
      );

      await this.securityLogger.logAuthAttempt(
        'gRPC_TELEGRAM',
        `telegram_${telegramId}`,
        true,
      );

      return {
        accessToken: encryptedAccessToken,
        refreshToken: encryptedRefreshToken,
        isNewUser,
      };
    } catch (error) {
      await this.securityLogger.logAuthAttempt(
        'gRPC_TELEGRAM',
        `telegram_${telegramId}`,
        false,
      );

      // Безопасная обработка ошибок
      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(`Telegram auth error: ${(error as Error).message}`);

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Authentication failed',
      });
    }
  }

  @GrpcMethod('AuthService', 'telegramLogin')
  async telegramLogin(
    data: TelegramLoginRequest,
    metadata?: any,
  ): Promise<TelegramLoginResponse> {
    const { telegramId, authDate, hash } = data;

    this.logger.log(
      `📱 [TELEGRAM] LOGIN request received for Telegram ID: ${telegramId}`,
    );

    try {
      // 1. Валидация входных данных
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

      if (!authDate || !hash || authDate.length > 20 || hash.length > 100) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Missing or invalid authentication data',
        });
      }

      // 2. Проверяем brute force блокировку
      const isBlocked = await this.bruteForceService.isBlocked(
        `telegram_${telegramId}`,
      );
      if (isBlocked) {
        await this.securityLogger.logAuthAttempt(
          'gRPC_TELEGRAM_LOGIN',
          `telegram_${telegramId}`,
          false,
        );
        throw new RpcException({
          code: status.RESOURCE_EXHAUSTED,
          message: 'Too many failed attempts. Please try again later.',
        });
      }

      // 3. Находим пользователя одним запросом
      const user = await this.prismaService.user.findUnique({
        where: { telegramId },
        select: {
          id: true,
          email: true,
          telegramId: true,
          telegramFirstName: true,
          telegramLastName: true,
          telegramUsername: true,
          telegramPhotoUrl: true,
          isTelegramVerified: true,
        },
      });

      if (!user || !user.isTelegramVerified) {
        await this.bruteForceService.recordFailedAttempt(
          `telegram_${telegramId}`,
        );
        await this.securityLogger.logAuthAttempt(
          'gRPC_TELEGRAM_LOGIN',
          `telegram_${telegramId}`,
          false,
        );
        throw new RpcException({
          code: status.NOT_FOUND,
          message: 'User not found or not verified via Telegram.',
        });
      }

      // 5. Проверяем время authDate (базовая валидация времени)
      const authTimestamp = parseInt(authDate, 10);

      // Проверка на валидность timestamp
      if (
        isNaN(authTimestamp) ||
        authTimestamp <= 0 ||
        authTimestamp > 9999999999
      ) {
        await this.bruteForceService.recordFailedAttempt(
          `telegram_${telegramId}`,
        );
        await this.securityLogger.logAuthAttempt(
          'gRPC_TELEGRAM_LOGIN',
          `telegram_${telegramId}`,
          false,
        );
        throw new RpcException({
          code: status.UNAUTHENTICATED,
          message: 'Invalid authentication timestamp',
        });
      }

      const currentTimestamp = Math.floor(Date.now() / 1000);
      const maxAge = 24 * 60 * 60; // 24 часа

      if (isNaN(authTimestamp) || currentTimestamp - authTimestamp > maxAge) {
        await this.bruteForceService.recordFailedAttempt(
          `telegram_${telegramId}`,
        );
        await this.securityLogger.logAuthAttempt(
          'gRPC_TELEGRAM_LOGIN',
          `telegram_${telegramId}`,
          false,
        );
        throw new RpcException({
          code: status.UNAUTHENTICATED,
          message: 'Authentication data expired or invalid',
        });
      }

      // 6. Обновляем Oracle username при логине (гармонизация с Telegram)
      await this.telegramAuthService.updateOracleUsernameOnLogin(telegramId);

      // 7. Генерируем токены
      const tokens = await this.telegramAuthService.generateTokens(
        user.id,
        user.email,
      );

      // 8. Шифруем токены
      const encryptedAccessToken = this.encryptionService.encrypt(
        tokens.accessToken,
      );
      const encryptedRefreshToken = this.encryptionService.encrypt(
        tokens.refreshToken,
      );

      // 9. Валидация длины зашифрованных токенов
      if (
        encryptedAccessToken.length > 5000 ||
        encryptedRefreshToken.length > 5000
      ) {
        throw new RpcException({
          code: status.INTERNAL,
          message: 'Token encryption failed',
        });
      }

      // 10. Очищаем счетчик неудачных попыток
      await this.bruteForceService.clearFailedAttempts(
        `telegram_${telegramId}`,
      );

      await this.securityLogger.logAuthAttempt(
        'gRPC_TELEGRAM_LOGIN',
        `telegram_${telegramId}`,
        true,
      );

      return {
        accessToken: encryptedAccessToken,
        refreshToken: encryptedRefreshToken,
      };
    } catch (error) {
      await this.securityLogger.logAuthAttempt(
        'gRPC_TELEGRAM_LOGIN',
        `telegram_${telegramId}`,
        false,
      );

      // Безопасная обработка ошибок
      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(`Telegram login error: ${(error as Error).message}`);

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Authentication failed',
      });
    }
  }

  @GrpcMethod('AuthService', 'linkTelegramAccount')
  async linkTelegramAccount(
    data: LinkTelegramRequest,
  ): Promise<LinkTelegramResponse> {
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

    this.logger.log(
      `🔗 [TELEGRAM] LINK request received for user ${userId} and Telegram ID: ${telegramId}`,
    );

    try {
      // 1. Валидация входных данных
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

      if (lastName && lastName.length > 100) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid last name',
        });
      }

      if (username && username.length > 50) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid username',
        });
      }

      if (photoUrl && photoUrl.length > 500) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid photo URL',
        });
      }

      if (!authDate || !hash || authDate.length > 20 || hash.length > 100) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Missing or invalid authentication data',
        });
      }

      // 2. Валидируем Telegram данные
      const authData = {
        telegramId: telegramId,
        firstName: firstName,
        lastName: lastName,
        username,
        photoUrl: photoUrl,
        authDate: authDate,
        hash,
      };

      const isValid = this.telegramAuthService.validateTelegramAuth(authData);
      if (!isValid) {
        this.securityLogger.logSecurityError(
          'TELEGRAM_LINK_FAILED',
          'Invalid Telegram authentication data',
        );
        return {
          success: false,
          message: 'Invalid Telegram authentication data',
        };
      }

      // 2. Привязываем Telegram к существующему аккаунту
      const success =
        await this.telegramAuthService.linkTelegramToExistingAccount(
          userId,
          authData,
        );

      if (success) {
        this.securityLogger.logJwtEvent(
          'TELEGRAM_LINKED',
          `User ${userId} linked Telegram account ${telegramId}`,
        );
        return {
          success: true,
          message: 'Telegram account linked successfully',
        };
      } else {
        return {
          success: false,
          message: 'Failed to link Telegram account',
        };
      }
    } catch (error) {
      this.securityLogger.logSecurityError(
        'TELEGRAM_LINK_FAILED',
        (error as Error).message,
      );

      // Безопасная обработка ошибок
      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(`Telegram link error: ${(error as Error).message}`);

      return {
        success: false,
        message: 'Failed to link Telegram account',
      };
    }
  }

  // Seed Phrase Methods
  @GrpcMethod('AuthService', 'enableSeedPhrase')
  @Throttle({ default: { ttl: 300000, limit: 5 } }) // 5 попыток в 5 минут
  async enableSeedPhrase(
    data: EnableSeedPhraseRequest,
  ): Promise<EnableSeedPhraseResponse> {
    const { userId, seedPhrase } = data;

    this.logger.log(`🔐 [SEED] ENABLE request received for user ${userId}`);

    try {
      // 1. Валидация входных данных
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

      // 2. Проверяем сложность seed фразы (минимум 12 слов)
      const words = seedPhrase.trim().split(/\s+/);
      if (words.length < 12) {
        this.securityLogger.logSecurityError(
          'SEED_PHRASE_ENABLE_FAILED',
          `User ${userId} attempted to enable seed phrase with insufficient words: ${words.length}`,
        );
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Seed phrase must contain at least 12 words',
        });
      }

      // 3. Проверяем существование пользователя
      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new RpcException({
          code: status.NOT_FOUND,
          message: 'User not found',
        });
      }

      // 4. Включаем seed фразу
      const result = await this.authService.enableSeedPhrase(data);

      // 5. Логируем успешное включение
      this.securityLogger.logJwtEvent(
        'SEED_PHRASE_ENABLED',
        `User ${userId} enabled seed phrase`,
      );

      return result;
    } catch (error) {
      this.securityLogger.logSecurityError(
        'SEED_PHRASE_ENABLE_FAILED',
        (error as Error).message,
      );

      // Безопасная обработка ошибок
      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(
        `Seed phrase enable error: ${(error as Error).message}`,
      );

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to enable seed phrase',
      });
    }
  }

  @GrpcMethod('AuthService', 'verifySeedPhrase')
  @Throttle({ default: { ttl: 60000, limit: 10 } }) // 10 попыток в минуту
  async verifySeedPhrase(
    data: VerifySeedPhraseRequest,
  ): Promise<VerifySeedPhraseResponse> {
    const { userId, seedPhrase } = data;

    this.logger.log(`🔐 [SEED] VERIFY request received for user ${userId}`);

    try {
      // 1. Валидация входных данных
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

      // 2. Проверяем brute force блокировку для seed фразы
      const isBlocked = await this.bruteForceService.isBlocked(
        `seed_${userId}`,
      );
      if (isBlocked) {
        await this.securityLogger.logAuthAttempt(
          'gRPC_SEED',
          `seed_${userId}`,
          false,
        );
        throw new RpcException({
          code: status.RESOURCE_EXHAUSTED,
          message: 'Too many failed attempts. Please try again later.',
        });
      }

      // 3. Проверяем seed фразу
      const result = await this.authService.verifySeedPhrase(data);

      if (result.success) {
        // 4. Очищаем счетчик неудачных попыток
        await this.bruteForceService.clearFailedAttempts(`seed_${userId}`);

        // 5. Анализ аномалий поведения
        const behavior = {
          userId: userId,
          ipAddress: 'seed_verification',
          userAgent: 'seed_phrase_verification',
          action: 'seed_verify',
          success: true,
          timestamp: new Date(),
        };

        const anomalyScore =
          await this.anomalyDetectionService.analyzeUserBehavior(
            userId,
            behavior,
          );

        if (anomalyScore.score > 0.7) {
          this.securityLogger.logAnomaly(
            'gRPC_SEED',
            `seed_${userId}`,
            anomalyScore,
          );
        }

        // 6. Логируем успешную проверку
        await this.securityLogger.logAuthAttempt(
          'gRPC_SEED',
          `seed_${userId}`,
          true,
        );
        this.securityLogger.logJwtEvent(
          'SEED_PHRASE_VERIFIED',
          `User ${userId} verified seed phrase successfully`,
        );

        return result;
      } else {
        // 7. Записываем неудачную попытку
        await this.bruteForceService.recordFailedAttempt(`seed_${userId}`);
        await this.securityLogger.logAuthAttempt(
          'gRPC_SEED',
          `seed_${userId}`,
          false,
        );

        throw new RpcException({
          code: status.PERMISSION_DENIED,
          message: result.message,
        });
      }
    } catch (error) {
      await this.securityLogger.logAuthAttempt(
        'gRPC_SEED',
        `seed_${userId}`,
        false,
      );

      // Безопасная обработка ошибок
      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(
        `Seed phrase verify error: ${(error as Error).message}`,
      );

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to verify seed phrase',
      });
    }
  }

  @GrpcMethod('AuthService', 'disableSeedPhrase')
  @Throttle({ default: { ttl: 300000, limit: 3 } }) // 3 попытки в 5 минут
  async disableSeedPhrase(
    data: DisableSeedPhraseRequest,
  ): Promise<DisableSeedPhraseResponse> {
    const { userId, seedPhrase } = data;

    this.logger.log(`🔐 [SEED] DISABLE request received for user ${userId}`);

    try {
      // 1. Валидация входных данных
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

      // 2. Отключаем seed фразу
      const result = await this.authService.disableSeedPhrase(data);

      // 3. Логируем отключение
      this.securityLogger.logJwtEvent(
        'SEED_PHRASE_DISABLED',
        `User ${userId} disabled seed phrase`,
      );

      return result;
    } catch (error) {
      this.securityLogger.logSecurityError(
        'SEED_PHRASE_DISABLE_FAILED',
        (error as Error).message,
      );

      // Безопасная обработка ошибок
      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(
        `Seed phrase disable error: ${(error as Error).message}`,
      );

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to disable seed phrase',
      });
    }
  }

  @GrpcMethod('AuthService', 'getSeedPhraseStatus')
  async getSeedPhraseStatus(
    data: GetSeedPhraseStatusRequest,
  ): Promise<GetSeedPhraseStatusResponse> {
    const { userId } = data;

    this.logger.log(`🔐 [SEED] STATUS request received for user ${userId}`);

    try {
      // 1. Валидация входных данных
      if (!userId || userId.trim().length === 0 || userId.length > 100) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid user ID',
        });
      }

      // 2. Получаем статус seed фразы
      const result = await this.authService.getSeedPhraseStatus(data);

      // 3. Логируем запрос статуса
      this.securityLogger.logJwtEvent(
        'SEED_PHRASE_STATUS',
        `User ${userId} requested seed phrase status`,
      );

      return result;
    } catch (error) {
      this.securityLogger.logSecurityError(
        'SEED_PHRASE_STATUS_FAILED',
        (error as Error).message,
      );

      // Безопасная обработка ошибок
      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(
        `Seed phrase status error: ${(error as Error).message}`,
      );

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to get seed phrase status',
      });
    }
  }

  // User profile management methods
  @GrpcMethod('AuthService', 'changePassword')
  @Throttle({ default: { ttl: 300000, limit: 5 } }) // 5 попыток в 5 минут
  async changePassword(
    data: ChangePasswordRequest,
  ): Promise<ChangePasswordResponse> {
    const { userId, currentPassword, newPassword } = data;

    this.logger.log(`🔐 [PASSWORD] CHANGE request received for user ${userId}`);

    try {
      // 1. Валидация входных данных
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

      // 2. Проверяем сложность нового пароля
      const passwordValidation =
        this.secureAuthService.validatePasswordStrength(newPassword);
      if (!passwordValidation.valid) {
        this.securityLogger.logSecurityError(
          'PASSWORD_CHANGE_FAILED',
          `User ${userId} attempted to set weak password: ${passwordValidation.errors.join(', ')}`,
        );
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: `Password validation failed: ${passwordValidation.errors.join(', ')}`,
        });
      }

      // 3. Меняем пароль
      const result = await this.authService.changePassword(data);

      // 4. Логируем успешное изменение
      this.securityLogger.logJwtEvent(
        'PASSWORD_CHANGED',
        `User ${userId} changed password successfully`,
      );

      return result;
    } catch (error) {
      this.securityLogger.logSecurityError(
        'PASSWORD_CHANGE_FAILED',
        (error as Error).message,
      );

      // Безопасная обработка ошибок
      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(`Password change error: ${(error as Error).message}`);

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to change password',
      });
    }
  }

  @GrpcMethod('AuthService', 'changeEmail')
  @Throttle({ default: { ttl: 300000, limit: 3 } }) // 3 попытки в 5 минут
  async changeEmail(data: ChangeEmailRequest): Promise<ChangeEmailResponse> {
    const { userId, currentPassword, newEmail } = data;

    this.logger.log(`📧 [EMAIL] CHANGE request received for user ${userId}`);

    try {
      // 1. Валидация входных данных
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

      // 2. Валидация формата email
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(newEmail)) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid email format',
        });
      }

      // 3. Меняем email
      const result = await this.authService.changeEmail(data);

      // 4. Логируем успешное изменение
      this.securityLogger.logJwtEvent(
        'EMAIL_CHANGED',
        `User ${userId} changed email to ${newEmail}`,
      );

      return result;
    } catch (error) {
      this.securityLogger.logSecurityError(
        'EMAIL_CHANGE_FAILED',
        (error as Error).message,
      );

      // Безопасная обработка ошибок
      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(`Email change error: ${(error as Error).message}`);

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to change email',
      });
    }
  }

  @GrpcMethod('AuthService', 'changeTelegramAccount')
  @Throttle({ default: { ttl: 300000, limit: 5 } }) // 5 попыток в 5 минут
  async changeTelegramAccount(
    data: ChangeTelegramAccountRequest,
  ): Promise<ChangeTelegramAccountResponse> {
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

    this.logger.log(`📱 [TELEGRAM] CHANGE request received for user ${userId}`);

    try {
      // 1. Валидация входных данных
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

      // 2. Валидируем Telegram данные
      const authData = {
        telegramId: telegramId,
        firstName: firstName,
        lastName: lastName,
        username,
        photoUrl: photoUrl,
        authDate: authDate,
        hash,
      };

      const isValid = this.telegramAuthService.validateTelegramAuth(authData);
      if (!isValid) {
        this.securityLogger.logSecurityError(
          'TELEGRAM_CHANGE_FAILED',
          `User ${userId} provided invalid Telegram authentication data`,
        );
        throw new RpcException({
          code: status.UNAUTHENTICATED,
          message: 'Invalid Telegram authentication data',
        });
      }

      // 3. Меняем Telegram аккаунт
      const result = await this.authService.changeTelegramAccount(data);

      // 4. Логируем успешное изменение
      this.securityLogger.logJwtEvent(
        'TELEGRAM_ACCOUNT_CHANGED',
        `User ${userId} changed Telegram account to ${telegramId}`,
      );

      return result;
    } catch (error) {
      this.securityLogger.logSecurityError(
        'TELEGRAM_CHANGE_FAILED',
        (error as Error).message,
      );

      // Безопасная обработка ошибок
      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(
        `Telegram account change error: ${(error as Error).message}`,
      );

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to change Telegram account',
      });
    }
  }

  @GrpcMethod('AuthService', 'terminateAllSessions')
  @Throttle({ default: { ttl: 60000, limit: 3 } }) // 3 попытки в минуту
  async terminateAllSessions(
    data: TerminateAllSessionsRequest,
  ): Promise<TerminateAllSessionsResponse> {
    const { userId } = data;

    this.logger.log(
      `🔒 [SESSIONS] TERMINATE_ALL request received for user ${userId}`,
    );

    try {
      // 1. Валидация входных данных
      if (!userId || userId.trim().length === 0 || userId.length > 100) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid user ID',
        });
      }

      // 2. Завершаем все сессии
      const result = await this.authService.terminateAllSessions(data);

      // 3. Логируем успешное завершение сессий
      this.securityLogger.logJwtEvent(
        'ALL_SESSIONS_TERMINATED',
        `User ${userId} terminated ${result.terminatedSessions} sessions`,
      );

      return result;
    } catch (error) {
      this.securityLogger.logSecurityError(
        'SESSIONS_TERMINATION_FAILED',
        (error as Error).message,
      );

      // Безопасная обработка ошибок
      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(
        `Terminate sessions error: ${(error as Error).message}`,
      );

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to terminate sessions',
      });
    }
  }

  // Link email to existing account
  @GrpcMethod('AuthService', 'linkEmailToAccount')
  @Throttle({ default: { ttl: 300000, limit: 3 } }) // 3 попытки в 5 минут
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

  // Sync Oracle Username with Telegram data
  @GrpcMethod('AuthService', 'syncOracleUsername')
  @Throttle({ default: { ttl: 60000, limit: 10 } }) // 10 попыток в минуту
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
  @GrpcMethod('AuthService', 'changeOracleUsername')
  @Throttle({ default: { ttl: 300000, limit: 5 } }) // 5 попыток в 5 минут
  async changeOracleUsername(
    data: ChangeOracleUsernameRequest,
  ): Promise<ChangeOracleUsernameResponse> {
    const { userId, newUsername } = data;

    this.logger.log(`🔄 [ORACLE] Username change request for user ${userId}`);

    try {
      // 1. Валидация входных данных
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

      // 2. Изменяем Oracle username
      const result = await this.authService.changeOracleUsername(data);

      // 3. Логируем успешное изменение
      this.securityLogger.logJwtEvent(
        'ORACLE_USERNAME_CHANGED',
        `User ${userId} changed Oracle username to ${newUsername}`,
      );

      return result;
    } catch (error) {
      this.securityLogger.logSecurityError(
        'ORACLE_USERNAME_CHANGE_FAILED',
        (error as Error).message,
      );

      // Безопасная обработка ошибок
      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(
        `Oracle username change error: ${(error as Error).message}`,
      );

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to change Oracle username',
      });
    }
  }

  @GrpcMethod('AuthService', 'changeOracleNickName')
  @Throttle({ default: { ttl: 300000, limit: 10 } }) // 10 попыток в 5 минут
  async changeOracleNickName(
    data: ChangeOracleNickNameRequest,
  ): Promise<ChangeOracleNickNameResponse> {
    const { userId, newNickname } = data;

    this.logger.log(`🔄 [ORACLE] NickName change request for user ${userId}`);

    try {
      // 1. Валидация входных данных
      if (!userId || userId.trim().length === 0 || userId.length > 100) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid user ID',
        });
      }

      if (
        !newNickname ||
        newNickname.trim().length === 0 ||
        newNickname.length > 100
      ) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid nickname',
        });
      }

      // 2. Изменяем Oracle nickname
      const result = await this.authService.changeOracleNickName(data);

      // 3. Логируем успешное изменение
      this.securityLogger.logJwtEvent(
        'ORACLE_NICKNAME_CHANGED',
        `User ${userId} changed Oracle nickname to ${newNickname}`,
      );

      return result;
    } catch (error) {
      this.securityLogger.logSecurityError(
        'ORACLE_NICKNAME_CHANGE_FAILED',
        (error as Error).message,
      );

      // Безопасная обработка ошибок
      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(
        `Oracle nickname change error: ${(error as Error).message}`,
      );

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to change Oracle nickname',
      });
    }
  }

  @GrpcMethod('AuthService', 'getOracleIdentity')
  async getOracleIdentity(
    data: GetOracleIdentityRequest,
  ): Promise<GetOracleIdentityResponse> {
    const { userId } = data;

    this.logger.log(`🔄 [ORACLE] Identity request for user ${userId}`);

    try {
      // 1. Валидация входных данных
      if (!userId || userId.trim().length === 0 || userId.length > 100) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid user ID',
        });
      }

      // 2. Получаем Oracle identity
      const result = await this.authService.getOracleIdentity(data);

      // 3. Логируем запрос
      this.securityLogger.logJwtEvent(
        'ORACLE_IDENTITY_REQUESTED',
        `User ${userId} requested Oracle identity`,
      );

      return result;
    } catch (error) {
      this.securityLogger.logSecurityError(
        'ORACLE_IDENTITY_REQUEST_FAILED',
        (error as Error).message,
      );

      // Безопасная обработка ошибок
      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(
        `Oracle identity request error: ${(error as Error).message}`,
      );

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to get Oracle identity',
      });
    }
  }

  @GrpcMethod('AuthService', 'suggestOracleUsernameAlternatives')
  async suggestOracleUsernameAlternatives(
    data: SuggestOracleUsernameAlternativesRequest,
  ): Promise<SuggestOracleUsernameAlternativesResponse> {
    const { userId, desiredUsername, maxAlternatives } = data;

    this.logger.log(
      `🔄 [ORACLE] Username alternatives request for user ${userId}, desired: ${desiredUsername}`,
    );

    try {
      // 1. Валидация входных данных
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

      // 2. Получаем альтернативы
      const result = await this.authService.suggestUsernameAlternatives(data);

      // 3. Логируем запрос
      this.securityLogger.logJwtEvent(
        'ORACLE_USERNAME_ALTERNATIVES_REQUESTED',
        `User ${userId} requested alternatives for username: ${desiredUsername}`,
      );

      return result;
    } catch (error) {
      this.securityLogger.logSecurityError(
        'ORACLE_USERNAME_ALTERNATIVES_REQUEST_FAILED',
        (error as Error).message,
      );

      // Безопасная обработка ошибок
      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(
        `Oracle username alternatives request error: ${(error as Error).message}`,
      );

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to suggest username alternatives',
      });
    }
  }
}
