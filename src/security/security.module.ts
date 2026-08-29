import { Module } from '@nestjs/common';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';

import { SecurityLoggerService } from './security-logger.service';
import { BruteForceService } from './services/brute-force.service';
import { SecureAuthService } from './services/secure-auth.service';
import { EnhancedJwtService } from './services/enhanced-jwt.service';
import { TlsSecurityService } from './services/tls-security.service';
import { TwoFactorAuthService } from './services/two-factor-auth.service';
import { AnomalyDetectionService } from './services/anomaly-detection.service';
import { EncryptionService } from './services/encryption.service';
import { PrismaService } from '../prisma.service';

@Module({
  imports: [
    ThrottlerModule.forRoot([
      {
        ttl: 60000, // 1 минута
        limit: 100, // максимум 100 запросов
      },
      {
        ttl: 3600000, // 1 час
        limit: 1000, // максимум 1000 запросов в час
      },
    ]),
    JwtModule.registerAsync({
      useFactory: (configService: ConfigService) => ({
        secret: configService.getOrThrow<string>('JWT_SUPER_SECRET_WORD'),
        signOptions: {
          expiresIn: configService.getOrThrow<string>('JWT_EXPIRES_IN'),
        },
      }),
      inject: [ConfigService],
    }),
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
    SecurityLoggerService,
    BruteForceService,
    SecureAuthService,
    EnhancedJwtService,
    TlsSecurityService,
    TwoFactorAuthService,
    AnomalyDetectionService,
    EncryptionService,
    PrismaService,
  ],
  exports: [
    SecurityLoggerService,
    BruteForceService,
    SecureAuthService,
    EnhancedJwtService,
    TlsSecurityService,
    TwoFactorAuthService,
    AnomalyDetectionService,
    EncryptionService,
  ],
})
export class SecurityModule {}
