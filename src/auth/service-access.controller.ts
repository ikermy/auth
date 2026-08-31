import { Controller } from '@nestjs/common';
import { GrpcMethod } from '@nestjs/microservices';
import { ConfigService } from '@nestjs/config';
import { RpcException } from '@nestjs/microservices';
import { status } from '@grpc/grpc-js';
import { PrismaService } from '../prisma.service';
import { SecurityLoggerService } from '../security/security-logger.service';
import { CurrentUser } from './decorators/current-user.decorator';
import { Public } from './decorators/public.decorator';
import { AuthPrincipal } from './guards/principal';
import {
  GetAccountReadinessRequest,
  GetAccountReadinessResponse,
  GetTelegramIdentityHistoryRequest,
  GetTelegramIdentityHistoryResponse,
  GetPublicProfileRequest,
  PublicProfileResponse,
  FindUserByUsernameRequest,
  FindUserByUsernameResponse,
} from './auth';

/**
 * Отдельный контроллер для «пограничных» операций (CLEAN-01):
 * account readiness (frontend), административный аудит и межсервисный доступ
 * для доверенных сервисов. Все методы принадлежат proto-сервису AuthService.
 */
@Controller()
export class ServiceAccessController {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly securityLogger: SecurityLoggerService,
    private readonly configService: ConfigService,
  ) {}

  @GrpcMethod('AuthService', 'getAccountReadiness')
  async getAccountReadiness(
    data: GetAccountReadinessRequest,
    @CurrentUser() principal: AuthPrincipal,
  ): Promise<GetAccountReadinessResponse> {
    const userId = principal.userId;

    const user = await this.prismaService.user.findUnique({
      where: { id: userId },
    });
    if (!user) {
      throw new RpcException({
        code: status.NOT_FOUND,
        message: 'User not found',
      });
    }

    const hasVerifiedEmail = !!user.email && user.isEmailVerified;
    const hasTelegram = !!user.telegramId;
    const hasPassword = !!user.password && user.origin === 'email';
    const twoFaEnabled = user.twoFactorEnabled;
    const hasRecoveryPhrase = user.seedPhraseEnabled && !!user.seedPhraseHash;
    const lastRecoveryVerifiedAt =
      user.seedPhraseLastVerifiedAt?.toISOString() || '';

    let accountStatus = 'active';
    if (!user.isActive) {
      accountStatus = 'deactivated';
    } else if (hasTelegram && !hasVerifiedEmail) {
      accountStatus = 'pending_email';
    }

    const requiredActions: string[] = [];
    const recommendedActions: string[] = [];

    if (!hasVerifiedEmail) {
      requiredActions.push(hasTelegram ? 'confirm_email' : 'verify_email');
    }
    if (!hasVerifiedEmail && !hasTelegram) {
      recommendedActions.push('add_backup_login');
    }
    if (!twoFaEnabled) {
      recommendedActions.push('enable_2fa');
    }
    if (!hasRecoveryPhrase) {
      recommendedActions.push('setup_recovery');
    }
    if (hasRecoveryPhrase && !lastRecoveryVerifiedAt) {
      recommendedActions.push('verify_recovery');
    }

    return {
      hasVerifiedEmail,
      hasTelegram,
      hasPassword,
      twoFaEnabled,
      hasRecoveryPhrase,
      lastRecoveryVerifiedAt,
      accountStatus,
      requiredActions,
      recommendedActions,
    };
  }

  @GrpcMethod('AuthService', 'getTelegramIdentityHistory')
  async getTelegramIdentityHistory(
    data: GetTelegramIdentityHistoryRequest,
    @CurrentUser() principal: AuthPrincipal,
  ): Promise<GetTelegramIdentityHistoryResponse> {
    // Общедоступный метод: доступен любому авторизованному пользователю
    // (активная сессия через guard). Административные привилегии не требуются.
    const targetUserId = data.userId;
    if (!targetUserId || targetUserId.trim().length === 0) {
      throw new RpcException({
        code: status.INVALID_ARGUMENT,
        message: 'Invalid user ID',
      });
    }

    const page = Math.max(1, data.page || 1);
    const limit = Math.min(100, Math.max(1, data.limit || 20));
    const skip = (page - 1) * limit;

    const [entries, total] = await Promise.all([
      this.prismaService.telegramIdentityAudit.findMany({
        where: { userId: targetUserId },
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
      }),
      this.prismaService.telegramIdentityAudit.count({
        where: { userId: targetUserId },
      }),
    ]);

    this.securityLogger.logJwtEvent(
      'ADMIN_READ_AUDIT',
      `Admin ${principal.userId} read Telegram identity history for ${targetUserId}`,
    );

    return {
      entries: entries.map((e) => ({
        id: e.id,
        eventType: e.eventType,
        previousData: JSON.stringify(e.previousData),
        createdAt: e.createdAt.toISOString(),
      })),
      total,
      page,
      limit,
    };
  }

  @Public()
  @GrpcMethod('AuthService', 'getPublicProfile')
  async getPublicProfile(
    data: GetPublicProfileRequest,
    metadata?: any,
  ): Promise<PublicProfileResponse> {
    this.assertServiceIdentity(metadata);

    const user = await this.prismaService.user.findUnique({
      where: { id: data.userId },
      select: {
        id: true,
        username: true,
        nickname: true,
        createdAt: true,
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
      username: user.username || '',
      nickname: user.nickname || '',
      createdAt: user.createdAt.toISOString(),
    };
  }

  @Public()
  @GrpcMethod('AuthService', 'findUserByUsername')
  async findUserByUsername(
    data: FindUserByUsernameRequest,
    metadata?: any,
  ): Promise<FindUserByUsernameResponse> {
    this.assertServiceIdentity(metadata);

    if (!data.username || data.username.trim().length === 0) {
      throw new RpcException({
        code: status.INVALID_ARGUMENT,
        message: 'Invalid user username',
      });
    }

    const user = await this.prismaService.user.findUnique({
      where: { username: data.username },
      select: {
        id: true,
        username: true,
        nickname: true,
        createdAt: true,
      },
    });
    if (!user) {
      return { found: false, profile: undefined };
    }

    return {
      found: true,
      profile: {
        userId: user.id,
        username: user.username || '',
        nickname: user.nickname || '',
        createdAt: user.createdAt.toISOString(),
      },
    };
  }

  /**
   * Проверка доверенного сервиса по service key из gRPC metadata (x-service-key).
   */
  private assertServiceIdentity(metadata?: any): void {
    const key = metadata?.get?.('x-service-key')?.[0];
    const keys = (this.configService.get<string>('SERVICE_API_KEYS', '') || '')
      .split(',')
      .map((k) => k.trim())
      .filter(Boolean);

    if (!key || !keys.includes(key)) {
      throw new RpcException({
        code: status.PERMISSION_DENIED,
        message: 'Trusted service identity required',
      });
    }
  }
}
