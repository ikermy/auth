import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { RpcException } from '@nestjs/microservices';
import { status } from '@grpc/grpc-js';
import { EmailVerificationService } from './email-verification.service';
import { PrismaService } from '../../prisma.service';

/** Достаёт gRPC-код из отклонённого RpcException. */
async function expectRpcError(
  promise: Promise<unknown>,
  expectedCode: number,
): Promise<void> {
  await expect(promise).rejects.toBeInstanceOf(RpcException);
  try {
    await promise;
  } catch (error) {
    const rpc = error as RpcException;
    expect((rpc.getError() as { code: number }).code).toBe(expectedCode);
  }
}

describe('EmailVerificationService', () => {
  let service: EmailVerificationService;
  let prisma: {
    user: {
      findUnique: jest.Mock;
      findFirst: jest.Mock;
      update: jest.Mock;
    };
  };

  const baseUser = {
    id: 'user-1',
    email: 'user@example.com',
    isEmailVerified: false,
    emailVerificationExpiresAt: null as Date | null,
  };

  beforeEach(async () => {
    prisma = {
      user: {
        findUnique: jest.fn(),
        findFirst: jest.fn(),
        update: jest.fn().mockResolvedValue({}),
      },
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        EmailVerificationService,
        { provide: PrismaService, useValue: prisma },
        {
          provide: ConfigService,
          useValue: { get: jest.fn() }, // → дефолтный TTL 1440 мин
        },
      ],
    }).compile();

    service = module.get(EmailVerificationService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('issueForUser', () => {
    it('rejects invalid user ID', async () => {
      await expectRpcError(
        service.issueForUser(''),
        status.INVALID_ARGUMENT,
      );
    });

    it('rejects unknown user', async () => {
      prisma.user.findUnique.mockResolvedValue(null);
      await expectRpcError(
        service.issueForUser('user-1'),
        status.NOT_FOUND,
      );
    });

    it('rejects user without a real email', async () => {
      prisma.user.findUnique.mockResolvedValue({
        ...baseUser,
        email: null,
      });
      await expectRpcError(
        service.issueForUser('user-1'),
        status.FAILED_PRECONDITION,
      );
    });

    it('rejects telegram placeholder email', async () => {
      prisma.user.findUnique.mockResolvedValue({
        ...baseUser,
        email: 'tg_123@secure.local',
      });
      await expectRpcError(
        service.issueForUser('user-1'),
        status.FAILED_PRECONDITION,
      );
    });

    it('rejects already verified email', async () => {
      prisma.user.findUnique.mockResolvedValue({
        ...baseUser,
        isEmailVerified: true,
      });
      await expectRpcError(
        service.issueForUser('user-1'),
        status.ALREADY_EXISTS,
      );
    });

    it('issues token and expiry for a valid user', async () => {
      prisma.user.findUnique.mockResolvedValue(baseUser);

      const result = await service.issueForUser('user-1');

      expect(result.email).toBe('user@example.com');
      expect(result.expiresAt.getTime()).toBeGreaterThan(Date.now());
      const updateArg = prisma.user.update.mock.calls[0][0];
      expect(updateArg.where).toEqual({ id: 'user-1' });
      expect(typeof updateArg.data.emailVerificationToken).toBe('string');
      expect(updateArg.data.emailVerificationToken.length).toBe(64);
      expect(
        updateArg.data.emailVerificationExpiresAt.getTime(),
      ).toBeGreaterThan(Date.now());
    });
  });

  describe('verify', () => {
    it('rejects empty token', async () => {
      await expectRpcError(service.verify(''), status.INVALID_ARGUMENT);
    });

    it('rejects unknown token', async () => {
      prisma.user.findFirst.mockResolvedValue(null);
      await expectRpcError(
        service.verify('unknown-token'),
        status.PERMISSION_DENIED,
      );
    });

    it('rejects already verified email', async () => {
      prisma.user.findFirst.mockResolvedValue({
        ...baseUser,
        isEmailVerified: true,
        emailVerificationExpiresAt: new Date(Date.now() + 60_000),
      });
      await expectRpcError(
        service.verify('token'),
        status.ALREADY_EXISTS,
      );
    });

    it('rejects expired token', async () => {
      prisma.user.findFirst.mockResolvedValue({
        ...baseUser,
        emailVerificationExpiresAt: new Date(Date.now() - 60_000),
      });
      await expectRpcError(
        service.verify('token'),
        status.PERMISSION_DENIED,
      );
    });

    it('rejects token without expiry', async () => {
      prisma.user.findFirst.mockResolvedValue({
        ...baseUser,
        emailVerificationExpiresAt: null,
      });
      await expectRpcError(
        service.verify('token'),
        status.PERMISSION_DENIED,
      );
    });

    it('verifies email and consumes the token', async () => {
      prisma.user.findFirst.mockResolvedValue({
        ...baseUser,
        emailVerificationExpiresAt: new Date(Date.now() + 60_000),
      });

      const result = await service.verify('valid-token');

      expect(result.email).toBe('user@example.com');
      const updateArg = prisma.user.update.mock.calls[0][0];
      expect(updateArg.where).toEqual({ id: 'user-1' });
      expect(updateArg.data.isEmailVerified).toBe(true);
      expect(updateArg.data.emailVerifiedAt).toBeInstanceOf(Date);
      expect(updateArg.data.emailVerificationToken).toBeNull();
      expect(updateArg.data.emailVerificationExpiresAt).toBeNull();
    });
  });
});
