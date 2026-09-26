import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { RpcException } from '@nestjs/microservices';
import { status } from '@grpc/grpc-js';
import * as crypto from 'crypto';
import { PrismaService } from '../../prisma.service';

const EMAIL_VERIFICATION_TOKEN_BYTES = 32;
const DEFAULT_TTL_MINUTES = 1440; // 24 часа
const MAX_TOKEN_LENGTH = 200;
const CONFIG_TTL_KEY = 'EMAIL_VERIFICATION_TTL_MINUTES';

/**
 * Верификация владения email.
 *
 * Выпускает одноразовый токен (хранится в users.emailVerificationToken) со сроком
 * жизни (users.emailVerificationExpiresAt) и подтверждает email по токену.
 *
 * Доставка токена получателю (SMTP/Notifications) — вне зоны ответственности
 * сервиса: без настроенного транспорта токен только сохраняется и логируется
 * факт выпуска. Верификация работает независимо от транспорта.
 */
@Injectable()
export class EmailVerificationService {
  private readonly logger = new Logger(EmailVerificationService.name);

  constructor(
    private readonly prismaService: PrismaService,
    private readonly configService: ConfigService,
  ) {}

  /** TTL токена в миллисекундах (из конфига, с безопасным дефолтом). */
  get ttlMs(): number {
    const configured = Number(
      this.configService.get<number>(CONFIG_TTL_KEY, DEFAULT_TTL_MINUTES),
    );
    const minutes =
      Number.isFinite(configured) && configured > 0
        ? configured
        : DEFAULT_TTL_MINUTES;
    return minutes * 60 * 1000;
  }

  /** Криптостойкий одноразовый токен (32 байта → 64 hex-символа). */
  generateToken(): string {
    return crypto.randomBytes(EMAIL_VERIFICATION_TOKEN_BYTES).toString('hex');
  }

  /** Срок истечения токена относительно переданного момента. */
  expiresAt(from: Date = new Date()): Date {
    return new Date(from.getTime() + this.ttlMs);
  }

  /**
   * Выпускает (перевыпускает) токен подтверждения email для пользователя.
   * Требует наличия реального (не placeholder) email и отсутствия подтверждения.
   */
  async issueForUser(
    userId: string,
  ): Promise<{ email: string; expiresAt: Date }> {
    if (!userId || userId.trim().length === 0 || userId.length > 100) {
      throw new RpcException({
        code: status.INVALID_ARGUMENT,
        message: 'Invalid user ID',
      });
    }

    const user = await this.prismaService.user.findUnique({
      where: { id: userId },
      select: { id: true, email: true, isEmailVerified: true },
    });

    if (!user) {
      throw new RpcException({
        code: status.NOT_FOUND,
        message: 'User not found',
      });
    }

    if (!user.email || user.email.startsWith('tg_')) {
      throw new RpcException({
        code: status.FAILED_PRECONDITION,
        message: 'No email address linked to verify',
      });
    }

    if (user.isEmailVerified) {
      throw new RpcException({
        code: status.ALREADY_EXISTS,
        message: 'Email is already verified',
      });
    }

    const token = this.generateToken();
    const expiresAt = this.expiresAt();

    await this.prismaService.user.update({
      where: { id: user.id },
      data: {
        emailVerificationToken: token,
        emailVerificationExpiresAt: expiresAt,
      },
    });

    // Сам токен не логируем.
    this.logger.log(
      `📧 [EMAIL] Verification token issued for user ${user.id} (expires ${expiresAt.toISOString()})`,
    );

    return { email: user.email, expiresAt };
  }

  /**
   * Подтверждает email по токену. Токен одноразовый и имеет TTL.
   */
  async verify(token: string): Promise<{ email: string }> {
    if (
      !token ||
      token.trim().length === 0 ||
      token.length > MAX_TOKEN_LENGTH
    ) {
      throw new RpcException({
        code: status.INVALID_ARGUMENT,
        message: 'Invalid email verification token',
      });
    }

    const user = await this.prismaService.user.findFirst({
      where: { emailVerificationToken: token },
      select: {
        id: true,
        email: true,
        isEmailVerified: true,
        emailVerificationExpiresAt: true,
      },
    });

    // Одинаковая ошибка для неизвестного и истёкшего токена — не раскрываем детали.
    const invalidToken = () =>
      new RpcException({
        code: status.PERMISSION_DENIED,
        message: 'Invalid or expired email verification token',
      });

    if (!user) {
      throw invalidToken();
    }

    if (user.isEmailVerified) {
      throw new RpcException({
        code: status.ALREADY_EXISTS,
        message: 'Email is already verified',
      });
    }

    if (
      !user.emailVerificationExpiresAt ||
      user.emailVerificationExpiresAt.getTime() < Date.now()
    ) {
      throw invalidToken();
    }

    await this.prismaService.user.update({
      where: { id: user.id },
      data: {
        isEmailVerified: true,
        emailVerifiedAt: new Date(),
        emailVerificationToken: null,
        emailVerificationExpiresAt: null,
      },
    });

    this.logger.log(`✅ [EMAIL] Email verified for user ${user.id}`);

    return { email: user.email ?? '' };
  }
}
