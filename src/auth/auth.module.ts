import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { TelegramAuthService } from './telegram-auth.service';
import { OracleUsernameService } from './services/oracle-username.service';
import { OracleIdentityService } from './services/oracle-identity.service';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma.service';
import { SecurityModule } from '../security/security.module';
import { HttpModule } from '@nestjs/axios';

@Module({
  imports: [
    JwtModule.registerAsync({
      useFactory: (configService: ConfigService) => ({
        global: true,
        secret: configService.getOrThrow<string>('JWT_SUPER_SECRET_WORD'),
        signOptions: {
          expiresIn: configService.getOrThrow<string>('JWT_EXPIRES_IN'),
        },
      }),
      inject: [ConfigService],
    }),
    HttpModule.register({
      timeout: 10000, // 10 секунд таймаут для HTTP запросов
      maxRedirects: 3,
    }),
    SecurityModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    TelegramAuthService,
    OracleUsernameService,
    OracleIdentityService,
    PrismaService,
  ],
})
export class AuthModule {}
