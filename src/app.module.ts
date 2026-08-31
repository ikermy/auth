import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ThrottlerModule } from '@nestjs/throttler';
import { JwtModule } from '@nestjs/jwt';
import { AuthModule } from './auth/auth.module';
import { SecurityModule } from './security/security.module';
import { PrismaModule } from './prisma.module';
import { CronModule } from './cron/cron.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    // Единый глобальный JwtModule (DI-01): доступен SecurityModule и AuthModule
    JwtModule.registerAsync({
      global: true,
      useFactory: (configService: ConfigService) => ({
        secret: configService.getOrThrow<string>('JWT_SECRET'),
      }),
      inject: [ConfigService],
    }),
    ThrottlerModule.forRoot([
      {
        ttl: 60000, // 1 минута
        limit: 100, // 100 запросов в минуту
      },
      {
        ttl: 3600000, // 1 час
        limit: 1000, // 1000 запросов в час
      },
    ]),
    PrismaModule,
    SecurityModule,
    AuthModule,
    CronModule,
  ],
  controllers: [],
})
export class AppModule {}
