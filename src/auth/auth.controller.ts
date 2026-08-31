import { Controller, Logger } from '@nestjs/common';
import { GrpcMethod, Payload } from '@nestjs/microservices';
import { BCRYPT_COST } from '../common/constants';
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
  Enable2FARequest,
  Verify2FARequest,
  Verify2FAResponse,
  Disable2FARequest,
  Disable2FAResponse,
  GetAnomalyStatsRequest,
} from './auth';
import { SecurityLoggerService } from '../security/security-logger.service';
import { BruteForceService } from '../security/services/brute-force.service';
import { SecureAuthService } from '../security/services/secure-auth.service';
import { EnhancedJwtService } from '../security/services/enhanced-jwt.service';
import { TwoFactorAuthService } from '../security/services/two-factor-auth.service';
import { AnomalyDetectionService } from '../security/services/anomaly-detection.service';
import { EncryptionService } from '../security/services/encryption.service';
import { UsernameService } from './services/username.service';
import { UserIdentityService } from './services/user-identity.service';
import { PrismaService } from '../prisma.service';
import { RpcException } from '@nestjs/microservices';
import { status } from '@grpc/grpc-js';
import { Throttle } from '@nestjs/throttler';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { Public } from './decorators/public.decorator';
import { CurrentUser } from './decorators/current-user.decorator';
import { AuthPrincipal } from './guards/principal';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { validateDto } from './dto/validate-dto';

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
    private readonly usernameService: UsernameService,
    private readonly userIdentityService: UserIdentityService,
    private readonly prismaService: PrismaService,
  ) {}

  @Public()
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
      // 1. Валидация входных данных через единый DTO-слой
      await validateDto(LoginDto, data);

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

      // 4. Генерируем токены с JTI (создаёт активную сессию)
      const tokens = await this.enhancedJwtService.generateTokens(
        authResult.user.id,
        authResult.user.email,
        { ipAddress, userAgent },
      );

      // 5. Проверяем 2FA статус пользователя
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
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
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

  @Public()
  @GrpcMethod('AuthService', 'register')
  @Throttle({ default: { ttl: 300000, limit: 3 } }) // 3 регистрации в 5 минут
  async register(data: RegisterRequest): Promise<RegisterResponse> {
    const { email, password } = data;

    this.logger.log(`📝 [AUTH] REGISTER request received for email: ${email}`);

    try {
      // 1. Валидация входных данных через единый DTO-слой
      await validateDto(RegisterDto, data);

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

      await this.securityLogger.logRegistration('gRPC', email, true);
      return {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
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

      await this.securityLogger.logTokenRefresh('gRPC', true);
      return {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
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
  async enable2FA(
    data: Enable2FARequest,
    @CurrentUser() principal: AuthPrincipal,
  ): Promise<{ qrCode: string; backupCodes: string[] }> {
    const userId = principal.userId;
    this.logger.log(`🔐 [2FA] ENABLE request received for user ${userId}`);

    try {
      // 1. Валидация входных данных
      if (
        !userId ||
        userId.trim().length === 0 ||
        userId.length > 100
      ) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid user ID',
        });
      }

      const result = await this.twoFactorAuthService.enable2FA(userId, '');
      this.securityLogger.logJwtEvent(
        '2FA_ENABLED',
        `User ${userId} enabled 2FA`,
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
  async verify2FA(
    data: Verify2FARequest,
    @CurrentUser() principal: AuthPrincipal,
  ): Promise<Verify2FAResponse> {
    const userId = principal.userId;
    this.logger.log(`🔐 [2FA] VERIFY request received for user ${userId}`);

    try {
      // 1. Валидация входных данных
      if (
        !userId ||
        userId.trim().length === 0 ||
        userId.length > 100
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
        where: { id: userId },
      });
      if (!user) {
        throw new Error('User not found');
      }

      let isValid: boolean;
      let backupCodes: string[] = [];
      if (user.twoFactorPendingSecret) {
        // Завершение настройки 2FA: подтверждение первого кода активирует фактор
        // и возвращает одноразовые backup-коды
        const result = await this.twoFactorAuthService.confirm2FA(
          userId,
          data.token,
        );
        isValid = result.success;
        backupCodes = result.backupCodes;
      } else if (user.twoFactorSecret) {
        // Проверка активного TOTP (например, при входе)
        isValid = this.twoFactorAuthService.verifyTOTP(
          user.twoFactorSecret,
          data.token,
        );
      } else {
        throw new Error('2FA not enabled for this user');
      }

      if (!isValid) {
        this.securityLogger.logJwtEvent(
          '2FA_VERIFIED',
          `User ${userId} 2FA verification: ${isValid}`,
        );
        return {
          success: false,
          accessToken: '',
          refreshToken: '',
          backupCodes: [],
        };
      }

      // Замыкаем поток: после успешного прохождения 2FA выдаём token pair
      const tokens = await this.enhancedJwtService.generateTokens(
        user.id,
        user.email,
      );

      this.securityLogger.logJwtEvent(
        '2FA_VERIFIED',
        `User ${userId} 2FA verification: ${isValid}`,
      );
      return {
        success: true,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        backupCodes,
      };
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

  @GrpcMethod('AuthService', 'disable2FA')
  async disable2FA(
    data: Disable2FARequest,
    @CurrentUser() principal: AuthPrincipal,
  ): Promise<Disable2FAResponse> {
    const userId = principal.userId;
    this.logger.log(`🔐 [2FA] DISABLE request received for user ${userId}`);

    try {
      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
      });
      if (!user) {
        throw new RpcException({
          code: status.NOT_FOUND,
          message: 'User not found',
        });
      }

      // Усиленное подтверждение: текущий пароль, если password-credential существует
      if (user.password) {
        if (
          !data.currentPassword ||
          data.currentPassword.trim().length === 0
        ) {
          throw new RpcException({
            code: status.INVALID_ARGUMENT,
            message: 'Current password is required to disable 2FA',
          });
        }
        const passwordOk = await bcrypt.compare(
          data.currentPassword,
          user.password,
        );
        if (!passwordOk) {
          throw new RpcException({
            code: status.PERMISSION_DENIED,
            message: 'Invalid current password',
          });
        }
      }

      // Усиленное подтверждение: активный TOTP, если 2FA включена
      if (user.twoFactorEnabled && user.twoFactorSecret) {
        if (!data.token || data.token.trim().length === 0) {
          throw new RpcException({
            code: status.INVALID_ARGUMENT,
            message: '2FA token is required to disable 2FA',
          });
        }
        const totpOk = this.twoFactorAuthService.verifyTOTP(
          user.twoFactorSecret,
          data.token,
        );
        if (!totpOk) {
          throw new RpcException({
            code: status.PERMISSION_DENIED,
            message: 'Invalid 2FA token',
          });
        }
      }

      await this.twoFactorAuthService.disable2FA(userId);

      this.securityLogger.logJwtEvent(
        '2FA_DISABLED',
        `User ${userId} disabled 2FA`,
      );
      return { success: true, message: '2FA disabled successfully' };
    } catch (error) {
      this.securityLogger.logSecurityError(
        '2FA_DISABLE_FAILED',
        (error as Error).message,
      );

      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(`2FA disable error: ${(error as Error).message}`);
      throw new RpcException({
        code: status.INTERNAL,
        message: '2FA disable failed',
      });
    }
  }

  @GrpcMethod('AuthService', 'getAnomalyStats')
  async getAnomalyStats(
    data: GetAnomalyStatsRequest,
    @CurrentUser() principal: AuthPrincipal,
  ): Promise<any> {
    const userId = principal.userId;
    this.logger.log(
      `📊 [ANOMALY] STATS request received for user ${userId}`,
    );

    try {
      // 1. Валидация входных данных
      if (
        !userId ||
        userId.trim().length === 0 ||
        userId.length > 100
      ) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid user ID',
        });
      }

      const stats = await this.anomalyDetectionService.getAnomalyStats(
        userId,
      );
      this.securityLogger.logJwtEvent(
        'ANOMALY_STATS',
        `Retrieved stats for user ${userId}`,
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

  @Public()
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

      // 6. Генерируем токены (создаёт активную сессию)
      const tokens = await this.enhancedJwtService.generateTokens(
        user.id,
        user.email,
        { ipAddress, userAgent },
      );

      // 7. Очищаем счетчик неудачных попыток
      await this.bruteForceService.clearFailedAttempts(
        `telegram_${telegramId}`,
      );

      await this.securityLogger.logAuthAttempt(
        'gRPC_TELEGRAM',
        `telegram_${telegramId}`,
        true,
      );

      return {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
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

  @Public()
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

      // 6. Обновляем User username при логине (гармонизация с Telegram)
      await this.telegramAuthService.updateUserUsernameOnLogin(telegramId);

      // 7. Генерируем токены (создаёт активную сессию)
      const tokens = await this.enhancedJwtService.generateTokens(
        user.id,
        user.email,
      );

      // 8. Очищаем счетчик неудачных попыток
      await this.bruteForceService.clearFailedAttempts(
        `telegram_${telegramId}`,
      );

      await this.securityLogger.logAuthAttempt(
        'gRPC_TELEGRAM_LOGIN',
        `telegram_${telegramId}`,
        true,
      );

      return {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
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
    @CurrentUser() principal: AuthPrincipal,
    metadata?: any,
  ): Promise<LinkTelegramResponse> {
    const {
      telegramId,
      firstName,
      lastName,
      username,
      photoUrl,
      authDate,
      hash,
    } = data;
    const userId = principal.userId;

    this.logger.log(
      `🔗 [TELEGRAM] LINK request received for user ${userId} and Telegram ID: ${telegramId}`,
    );

    try {
      // Повторное подтверждение для чувствительной операции (linking)
      await this.assertReauthentication(userId, metadata);

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
    @CurrentUser() principal: AuthPrincipal,
  ): Promise<EnableSeedPhraseResponse> {
    const { seedPhrase } = data;
    const userId = principal.userId;

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
    @CurrentUser() principal: AuthPrincipal,
  ): Promise<VerifySeedPhraseResponse> {
    const { seedPhrase } = data;
    const userId = principal.userId;

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
    @CurrentUser() principal: AuthPrincipal,
  ): Promise<DisableSeedPhraseResponse> {
    const { seedPhrase } = data;
    const userId = principal.userId;

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
    @CurrentUser() principal: AuthPrincipal,
  ): Promise<GetSeedPhraseStatusResponse> {
    const userId = principal.userId;

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
    @CurrentUser() principal: AuthPrincipal,
  ): Promise<ChangePasswordResponse> {
    const { currentPassword, newPassword } = data;
    const userId = principal.userId;

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
  async changeEmail(
    data: ChangeEmailRequest,
    @CurrentUser() principal: AuthPrincipal,
    metadata?: any,
  ): Promise<ChangeEmailResponse> {
    const { currentPassword, newEmail } = data;
    const userId = principal.userId;

    this.logger.log(`📧 [EMAIL] CHANGE request received for user ${userId}`);

    try {
      // Повторное подтверждение для чувствительной операции (смена email)
      await this.assertReauthentication(userId, metadata);

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
    @CurrentUser() principal: AuthPrincipal,
    metadata?: any,
  ): Promise<ChangeTelegramAccountResponse> {
    const {
      telegramId,
      firstName,
      lastName,
      username,
      photoUrl,
      authDate,
      hash,
    } = data;
    const userId = principal.userId;

    this.logger.log(`📱 [TELEGRAM] CHANGE request received for user ${userId}`);

    try {
      // Повторное подтверждение для чувствительной операции (смена Telegram)
      await this.assertReauthentication(userId, metadata);

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
    @CurrentUser() principal: AuthPrincipal,
  ): Promise<TerminateAllSessionsResponse> {
    const userId = principal.userId;

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
  async linkEmailToAccount(
    data: LinkEmailRequest,
    @CurrentUser() principal: AuthPrincipal,
    metadata?: any,
  ): Promise<LinkEmailResponse> {
    const { email, password } = data;
    const userId = principal.userId;

    this.logger.log(`📧 [EMAIL] LINK request received for user ${userId}`);

    try {
      // Повторное подтверждение для чувствительной операции (linking email)
      await this.assertReauthentication(userId, metadata);

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
      const saltRounds = BCRYPT_COST;
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

  // Sync User Username with Telegram data
  @GrpcMethod('AuthService', 'syncUsername')
  @Throttle({ default: { ttl: 60000, limit: 10 } }) // 10 попыток в минуту
  async syncUsername(
    data: SyncUsernameRequest,
    @CurrentUser() principal: AuthPrincipal,
  ): Promise<SyncUsernameResponse> {
    const userId = principal.userId;

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
      const newUserUsername =
        this.usernameService.generateUsername(
          user.telegramId,
          user.telegramUsername || undefined,
        );

      // 5. Проверяем, что новый username не занят другим пользователем
      if (newUserUsername !== user.username) {
        const existingUser = await this.prismaService.user.findUnique({
          where: { username: newUserUsername },
        });

        if (existingUser && existingUser.id !== userId) {
          // Генерируем альтернативные username
          const alternatives =
            await this.userIdentityService.generateUsernameAlternatives(
              newUserUsername,
              userId,
              5,
            );

          throw new RpcException({
            code: status.ALREADY_EXISTS,
            message: 'User username is already taken by another user',
            details: JSON.stringify({
              hasAlternatives: alternatives.length > 0,
              alternativeUsernames: alternatives,
            }),
          });
        }
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
  @GrpcMethod('AuthService', 'changeUsername')
  @Throttle({ default: { ttl: 300000, limit: 5 } }) // 5 попыток в 5 минут
  async changeUsername(
    @Payload() data: ChangeUsernameRequest,
    @CurrentUser() principal: AuthPrincipal,
  ): Promise<ChangeUsernameResponse> {
    const { newUsername } = data;
    const userId = principal.userId;

    this.logger.log(`🔄 [USER] Username change request for user ${userId}`);

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

      // 2. Изменяем User username
      const result = await this.authService.changeUsername({
        userId,
        newUsername,
      });

      // 3. Логируем успешное изменение
      this.securityLogger.logJwtEvent(
        'USER_USERNAME_CHANGED',
        `User ${userId} changed User username to ${newUsername}`,
      );

      return result;
    } catch (error) {
      this.securityLogger.logSecurityError(
        'USER_USERNAME_CHANGE_FAILED',
        (error as Error).message,
      );

      // Безопасная обработка ошибок
      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(
        `User username change error: ${(error as Error).message}`,
      );

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to change User username',
      });
    }
  }

  @GrpcMethod('AuthService', 'changeNickname')
  @Throttle({ default: { ttl: 300000, limit: 10 } }) // 10 попыток в 5 минут
  async changeNickname(
    @Payload() data: ChangeNicknameRequest,
    @CurrentUser() principal: AuthPrincipal,
  ): Promise<ChangeNicknameResponse> {
    const { newNickname } = data;
    const userId = principal.userId;

    this.logger.log(`🔄 [USER] NickName change request for user ${userId}`);

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

      // 2. Изменяем User nickname
      const result = await this.authService.changeNickname({
        userId,
        newNickname,
      });

      // 3. Логируем успешное изменение
      this.securityLogger.logJwtEvent(
        'USER_NICKNAME_CHANGED',
        `User ${userId} changed User nickname to ${newNickname}`,
      );

      return result;
    } catch (error) {
      this.securityLogger.logSecurityError(
        'USER_NICKNAME_CHANGE_FAILED',
        (error as Error).message,
      );

      // Безопасная обработка ошибок
      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(
        `User nickname change error: ${(error as Error).message}`,
      );

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to change User nickname',
      });
    }
  }

  @GrpcMethod('AuthService', 'changeTelegramUsername')
  @Throttle({ default: { ttl: 300000, limit: 10 } })
  async changeTelegramUsername(
    @Payload() data: ChangeTelegramUsernameRequest,
    @CurrentUser() principal: AuthPrincipal,
  ): Promise<ChangeTelegramUsernameResponse> {
    const telegramUsername = data?.telegramUsername || '';
    const userId = principal?.userId || data?.userId || '';

    this.logger.log(
      `🔄 [USER] Telegram username change request for user ${userId}`,
    );

    try {
      const result = await this.authService.changeTelegramUsername({
        userId,
        telegramUsername,
      });
      return result;
    } catch (error) {
      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(
        `User telegram username change error: ${(error as Error).message}`,
      );

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to change User telegram username',
      });
    }
  }

  @GrpcMethod('AuthService', 'changeAvatar')
  async changeAvatar(
    @Payload() data: ChangeAvatarRequest,
    @CurrentUser() principal: AuthPrincipal,
  ): Promise<ChangeAvatarResponse> {
    const photoBase64 = data?.photoBase64 || '';
    // userId из JWT-принципала (GrpcAuthGuard), fallback — из тела запроса.
    const userId = principal?.userId || data?.userId || '';

    this.logger.log(`🔄 [USER] Avatar change request for user ${userId}`);

    try {
      await this.authService.changeAvatar({ userId, photoBase64 });

      return {
        success: true,
        message: 'User avatar changed successfully',
      };
    } catch (error) {
      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(
        `User avatar change error: ${(error as Error).message}`,
      );

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to change User avatar',
      });
    }
  }

  @GrpcMethod('AuthService', 'getUserIdentity')
  async getUserIdentity(
    data: GetUserIdentityRequest,
    @CurrentUser() principal: AuthPrincipal,
  ): Promise<GetUserIdentityResponse> {
    const userId = principal.userId;

    this.logger.log(`🔄 [USER] Identity request for user ${userId}`);

    try {
      // 1. Валидация входных данных
      if (!userId || userId.trim().length === 0 || userId.length > 100) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Invalid user ID',
        });
      }

      // 2. Получаем User identity
      const result = await this.authService.getUserIdentity(data);

      // 3. Логируем запрос
      this.securityLogger.logJwtEvent(
        'USER_IDENTITY_REQUESTED',
        `User ${userId} requested User identity`,
      );

      return result;
    } catch (error) {
      this.securityLogger.logSecurityError(
        'USER_IDENTITY_REQUEST_FAILED',
        (error as Error).message,
      );

      // Безопасная обработка ошибок
      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(
        `User identity request error: ${(error as Error).message}`,
      );

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to get User identity',
      });
    }
  }

  @GrpcMethod('AuthService', 'getUserProfile')
  async getUserProfile(
    data: GetUserProfileRequest,
    @CurrentUser() principal: AuthPrincipal,
  ): Promise<GetUserProfileResponse> {
    const userId = principal?.userId || data?.userId || '';

    this.logger.log(`🔄 [USER] Profile request for user ${userId}`);

    try {
      const result = await this.authService.getUserProfile({ userId });
      return {
        success: result.success,
        message: result.message,
        userId: result.userId,
        email: result.email,
        username: result.username,
        nickname: result.nickname,
        photoBase64: result.photoBase64,
        telegramUsername: result.telegramUsername,
        telegramId: result.telegramId,
        telegramPhotoUrl: result.telegramPhotoUrl,
        origin: result.origin,
        isTelegramVerified: result.isTelegramVerified,
      };
    } catch (error) {
      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(
        `User profile retrieval error: ${(error as Error).message}`,
      );

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to get User profile',
      });
    }
  }

  @GrpcMethod('AuthService', 'suggestUsernameAlternatives')
  async suggestUsernameAlternatives(
    data: SuggestUsernameAlternativesRequest,
    @CurrentUser() principal: AuthPrincipal,
  ): Promise<SuggestUsernameAlternativesResponse> {
    const { desiredUsername, maxAlternatives } = data;
    const userId = principal.userId;

    this.logger.log(
      `🔄 [USER] Username alternatives request for user ${userId}, desired: ${desiredUsername}`,
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
        'USER_USERNAME_ALTERNATIVES_REQUESTED',
        `User ${userId} requested alternatives for username: ${desiredUsername}`,
      );

      return result;
    } catch (error) {
      this.securityLogger.logSecurityError(
        'USER_USERNAME_ALTERNATIVES_REQUEST_FAILED',
        (error as Error).message,
      );

      // Безопасная обработка ошибок
      if (error instanceof RpcException) {
        throw error;
      }

      this.logger.error(
        `User username alternatives request error: ${(error as Error).message}`,
      );

      throw new RpcException({
        code: status.INTERNAL,
        message: 'Failed to suggest username alternatives',
      });
    }
  }

  /**
   * Повторное подтверждение для чувствительных операций (§5.5 / §7 / §11):
   * текущий пароль (если есть password-credential) + активный TOTP (если 2FA включена).
   * Креды передаются клиентом в gRPC metadata: x-current-password, x-otp-token.
   */
  private async assertReauthentication(
    userId: string,
    metadata?: any,
  ): Promise<void> {
    const user = await this.prismaService.user.findUnique({
      where: { id: userId },
    });
    if (!user) {
      throw new RpcException({
        code: status.NOT_FOUND,
        message: 'User not found',
      });
    }

    const metadataGet = metadata?.get?.bind(metadata) || (() => []);

    if (user.password) {
      const currentPassword = metadataGet('x-current-password')?.[0];
      if (!currentPassword || currentPassword.trim().length === 0) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Reauthentication required: current password',
        });
      }
      const ok = await bcrypt.compare(currentPassword, user.password);
      if (!ok) {
        throw new RpcException({
          code: status.PERMISSION_DENIED,
          message: 'Reauthentication failed: invalid password',
        });
      }
    }

    if (user.twoFactorEnabled && user.twoFactorSecret) {
      const token = metadataGet('x-otp-token')?.[0];
      if (!token || token.trim().length === 0) {
        throw new RpcException({
          code: status.INVALID_ARGUMENT,
          message: 'Reauthentication required: 2FA token',
        });
      }
      const ok = this.twoFactorAuthService.verifyTOTP(
        user.twoFactorSecret,
        token,
      );
      if (!ok) {
        throw new RpcException({
          code: status.PERMISSION_DENIED,
          message: 'Reauthentication failed: invalid 2FA token',
        });
      }
    }
  }
}
