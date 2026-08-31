import { plainToInstance } from 'class-transformer';
import { validate, ValidationError } from 'class-validator';
import { RpcException } from '@nestjs/microservices';
import { status } from '@grpc/grpc-js';

/**
 * Валидирует plain-объект запроса по DTO-классу и бросает
 * RpcException(INVALID_ARGUMENT) при нарушении правил.
 * Обеспечивает единое определение правил валидации на границе gRPC
 * (вместо дублирования ручных проверок в контроллере и сервисе),
 * сохраняя детерминированный gRPC-код INVALID_ARGUMENT.
 */
export async function validateDto<T extends object>(
  dtoClass: new () => T,
  plain: unknown,
): Promise<T> {
  const instance = plainToInstance(dtoClass, plain as object);
  const errors: ValidationError[] = await validate(instance, {
    whitelist: true,
    forbidNonWhitelisted: false,
    stopAtFirstError: false,
  });

  if (errors.length > 0) {
    const messages = errors.flatMap((err) =>
      Object.values(err.constraints ?? {}),
    );
    throw new RpcException({
      code: status.INVALID_ARGUMENT,
      message: messages.join('; '),
    });
  }

  return instance;
}
