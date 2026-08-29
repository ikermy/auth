import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { SecurityLoggerService } from '../security/security-logger.service';

interface ClientMetadata {
  ipAddress?: string;
  userAgent?: string;
  forwardedFor?: string;
}

interface GrpcContext {
  clientMetadata?: ClientMetadata;
  get?: (key: string) => string[];
  peer?: string;
}

@Injectable()
export class GrpcMetadataInterceptor implements NestInterceptor {
  constructor(private readonly securityLogger: SecurityLoggerService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    try {
      const rpcContext = context.switchToRpc();
      // const metadata = rpcContext.getContext() as GrpcContext;
      const metadata: GrpcContext = rpcContext.getContext();

      // Извлекаем метаданные клиента из gRPC
      const clientMetadata = this.extractClientMetadata(metadata);

      // Логируем gRPC запрос
      this.securityLogger.logSuccess(
        clientMetadata.ipAddress || 'unknown',
        context.getHandler().name,
        context.getClass().name,
      );

      // Добавляем метаданные к контексту для использования в контроллерах
      metadata.clientMetadata = clientMetadata;

      return next.handle().pipe(
        tap({
          error: (error: Error) => {
            this.securityLogger.logError(
              clientMetadata.ipAddress || 'unknown',
              context.getHandler().name,
              context.getClass().name,
              error.message,
            );
          },
        }),
      );
    } catch (error) {
      this.securityLogger.logSecurityError(
        'INTERCEPTOR_ERROR',
        `Failed to intercept request: ${(error as Error).message}`,
      );
      return next.handle();
    }
  }

  private extractClientMetadata(metadata: GrpcContext): ClientMetadata {
    try {
      const clientMetadata: ClientMetadata = {};

      // Извлекаем IP адрес из различных заголовков
      if (metadata.get) {
        const xForwardedFor = metadata.get('x-forwarded-for');
        const xRealIp = metadata.get('x-real-ip');
        const userAgent = metadata.get('user-agent');

        // Валидация IP адреса
        let ipAddress =
          (xForwardedFor && xForwardedFor[0]) ||
          (xRealIp && xRealIp[0]) ||
          metadata.peer ||
          'unknown';

        // Ограничиваем длину IP адреса
        if (ipAddress.length > 45) {
          ipAddress = 'unknown';
        }

        // Валидация формата IP адреса
        if (!this.isValidIpAddress(ipAddress)) {
          ipAddress = 'unknown';
        }

        clientMetadata.ipAddress = ipAddress;

        // Валидация User-Agent
        if (userAgent && userAgent[0] && userAgent[0].length <= 500) {
          clientMetadata.userAgent = userAgent[0];
        }

        // Валидация X-Forwarded-For
        if (
          xForwardedFor &&
          xForwardedFor[0] &&
          xForwardedFor[0].length <= 45
        ) {
          clientMetadata.forwardedFor = xForwardedFor[0];
        }
      }

      return clientMetadata;
    } catch (error) {
      this.securityLogger.logSecurityError(
        'METADATA_EXTRACTION_ERROR',
        `Failed to extract client metadata: ${(error as Error).message}`,
      );
      return { ipAddress: 'unknown' };
    }
  }

  // Валидация IP адреса
  private isValidIpAddress(ip: string): boolean {
    try {
      // Проверка на IPv4
      const ipv4Regex =
        /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
      if (ipv4Regex.test(ip)) {
        return true;
      }

      // Проверка на IPv6
      const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;
      if (ipv6Regex.test(ip)) {
        return true;
      }

      // Проверка на localhost
      if (ip === 'localhost' || ip === '127.0.0.1' || ip === '::1') {
        return true;
      }

      return false;
    } catch (error) {
      return false;
    }
  }
}
