import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ThrottlerModule } from '@nestjs/throttler';
import { AuthModule } from './auth/auth.module';
import { SecurityModule } from './security/security.module';
import { PrismaService } from './prisma.service';
import { CronModule } from './cron/cron.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
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
    SecurityModule,
    AuthModule,
    CronModule,
  ],
  controllers: [],
  providers: [PrismaService],
  exports: [PrismaService],
})
export class AppModule {}
