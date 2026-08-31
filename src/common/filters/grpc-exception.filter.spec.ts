import { RpcException } from '@nestjs/microservices';
import { status } from '@grpc/grpc-js';
import { Prisma } from '../../../generated/prisma';
import { GrpcExceptionFilter } from './grpc-exception.filter';

const prismaError = (code: string) =>
  new Prisma.PrismaClientKnownRequestError('db error', {
    code,
    clientVersion: '6.0.0',
  });

const exec = (err: unknown) => {
  try {
    new GrpcExceptionFilter().catch(err, {} as any);
    return null;
  } catch (e) {
    return e;
  }
};

const rpcCode = (e: unknown) =>
  ((e as RpcException).getError() as { code: number }).code;

describe('GrpcExceptionFilter', () => {
  it('should map P2002 (unique) to ALREADY_EXISTS', () => {
    const err = exec(prismaError('P2002'));
    expect(rpcCode(err)).toBe(status.ALREADY_EXISTS);
  });

  it('should map P2003 (foreign key) to FAILED_PRECONDITION', () => {
    const err = exec(prismaError('P2003'));
    expect(rpcCode(err)).toBe(status.FAILED_PRECONDITION);
  });

  it('should map P2025 (not found) to NOT_FOUND', () => {
    const err = exec(prismaError('P2025'));
    expect(rpcCode(err)).toBe(status.NOT_FOUND);
  });

  it('should map unknown Prisma error to INTERNAL', () => {
    const err = exec(prismaError('P9999'));
    expect(rpcCode(err)).toBe(status.INTERNAL);
  });

  it('should rethrow RpcException as-is', () => {
    const original = new RpcException({
      code: status.PERMISSION_DENIED,
      message: 'denied',
    });
    const err = exec(original);
    expect(err).toBe(original);
  });

  it('should map generic error to INTERNAL', () => {
    const err = exec(new Error('boom'));
    expect(rpcCode(err)).toBe(status.INTERNAL);
  });
});
