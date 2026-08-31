import { Module } from '@nestjs/common';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { GrpcMetadataInterceptor } from '../interceptors/grpc-metadata.interceptor';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { ServiceAccessController } from './service-access.controller';
import { TelegramAuthService } from './telegram-auth.service';
import { UsernameService } from './services/username.service';
import { UserIdentityService } from './services/user-identity.service';
import { SecurityModule } from '../security/security.module';
import { HttpModule } from '@nestjs/axios';
import { GrpcAuthGuard } from './guards/grpc-auth.guard';
// GrpcExceptionFilter временно не подключён как APP_FILTER: бросок RpcException
// из catch в gRPC (watch) даёт connection dropped вместо кода ошибки.

@Module({
  imports: [
    HttpModule.register({
      timeout: 10000, // 10 секунд таймаут для HTTP запросов
      maxRedirects: 3,
    }),
    SecurityModule,
  ],
  controllers: [AuthController, ServiceAccessController],
  providers: [
    AuthService,
    TelegramAuthService,
    UsernameService,
    UserIdentityService,
    {
      provide: APP_GUARD,
      useClass: GrpcAuthGuard,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: GrpcMetadataInterceptor,
    },
  ],
})
export class AuthModule {}
