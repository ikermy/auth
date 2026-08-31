import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { MicroserviceOptions } from '@nestjs/microservices';
import { grpcConfig } from './config/app.config';
import { TlsSecurityService } from './security/services/tls-security.service';
import { Logger } from '@nestjs/common';
import { ValidationPipe } from '@nestjs/common';
// import { GrpcMetadataInterceptor } from './interceptors/grpc-metadata.interceptor';

async function bootstrap() {
  try {
    const app = await NestFactory.createMicroservice<MicroserviceOptions>(
      AppModule,
      grpcConfig,
    );

    // Корректное завершение: при сигнале SIGTERM/SIGINT вызываются
    // onModuleDestroy (Prisma $disconnect, закрытие Redis-клиентов)
    app.enableShutdownHooks();

    const logger = new Logger('Bootstrap');

    // Инициализируем TLS безопасность
    try {
      const tlsService = app.get(TlsSecurityService);
      if (tlsService.isTlsEnabled()) {
        logger.log(`🔒 [TLS] ENABLED on port ${tlsService.getTlsPort()}`);
      }
    } catch (error) {
      logger.error(`🔒 [TLS] ERROR: ${(error as Error).message}`);
    }

    // Подключаем глобальную валидацию
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    );

    // Подключаем gRPC метаданные интерцептор
    // const metadataInterceptor = app.get(GrpcMetadataInterceptor);
    // app.useGlobalInterceptors(metadataInterceptor);

    await app.listen();

    logger.log(
      '🚀 [SERVER] STARTED - Secure gRPC microservice is listening on port 50051',
    );
    logger.log('🛡️ [SECURITY] FEATURES_ENABLED:');
    logger.log('   • Rate limiting (100/min, 1000/hour)');
    logger.log('   • Security logging (real-time monitoring)');
    logger.log('   • JWT security (tokens, validation)');
    logger.log('   • User monitoring (daily + frequent checks)');
  } catch (error) {
    console.error(`💥 [BOOTSTRAP] CRITICAL ERROR: ${(error as Error).message}`);
    process.exit(1);
  }
}
void bootstrap();
