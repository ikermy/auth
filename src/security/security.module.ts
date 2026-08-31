import { Module } from '@nestjs/common';
import { ThrottlerModule } from '@nestjs/throttler';

import { SecurityLoggerService } from './security-logger.service';
import { BruteForceService } from './services/brute-force.service';
import { SecureAuthService } from './services/secure-auth.service';
import { EnhancedJwtService } from './services/enhanced-jwt.service';
import { TlsSecurityService } from './services/tls-security.service';
import { TwoFactorAuthService } from './services/two-factor-auth.service';
import { AnomalyDetectionService } from './services/anomaly-detection.service';
import { EncryptionService } from './services/encryption.service';
import { SessionService } from './services/session.service';
import { KafkaProducerService } from './services/kafka-producer.service';

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
  ],
  providers: [
    SecurityLoggerService,
    BruteForceService,
    SecureAuthService,
    EnhancedJwtService,
    TlsSecurityService,
    TwoFactorAuthService,
    AnomalyDetectionService,
    EncryptionService,
    SessionService,
    KafkaProducerService,
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
    SessionService,
    KafkaProducerService,
  ],
})
export class SecurityModule {}
