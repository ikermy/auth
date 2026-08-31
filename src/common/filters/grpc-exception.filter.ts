import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
} from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { status } from '@grpc/grpc-js';
import { Prisma } from '../../../generated/prisma';

interface GrpcStatusError {
  code: number;
  message: string;
}

/**
 * Единый gRPC-слой ошибок: превращает Prisma-ошибки и непредвиденные
 * исключения в стабильные gRPC-коды (RC-5 / DATA-01). Ожидаемые
 * конфликты уникальности больше не маскируются под INTERNAL.
 *
 * Маппинг Prisma:
 *  - P2002 (unique constraint)  -> ALREADY_EXISTS
 *  - P2003 (foreign key)        -> FAILED_PRECONDITION
 *  - P2025 (record not found)   -> NOT_FOUND
 *  - P2024 (pool exhausted)     -> UNAVAILABLE
 */
@Catch()
export class GrpcExceptionFilter implements ExceptionFilter {
  catch(exception: unknown, _host: ArgumentsHost): void {
    if (exception instanceof RpcException) {
      throw exception;
    }

    if (exception instanceof HttpException) {
      throw new RpcException({
        code: status.INVALID_ARGUMENT,
        message: exception.message,
      });
    }

    if (this.isPrismaError(exception)) {
      throw new RpcException(this.mapPrismaError(exception));
    }

    throw new RpcException({
      code: status.INTERNAL,
      message: 'Internal server error',
    });
  }

  private isPrismaError(exception: unknown): exception is Prisma.PrismaClientKnownRequestError {
    return (
      exception instanceof Prisma.PrismaClientKnownRequestError &&
      typeof (exception as Prisma.PrismaClientKnownRequestError).code === 'string'
    );
  }

  private mapPrismaError(
    error: Prisma.PrismaClientKnownRequestError,
  ): GrpcStatusError {
    switch (error.code) {
      case 'P2002':
        return {
          code: status.ALREADY_EXISTS,
          message: 'Resource already exists',
        };
      case 'P2003':
        return {
          code: status.FAILED_PRECONDITION,
          message: 'Referenced resource does not exist',
        };
      case 'P2025':
        return {
          code: status.NOT_FOUND,
          message: 'Resource not found',
        };
      case 'P2024':
        return {
          code: status.UNAVAILABLE,
          message: 'Database temporarily unavailable',
        };
      default:
        return {
          code: status.INTERNAL,
          message: 'Database error',
        };
    }
  }
}
