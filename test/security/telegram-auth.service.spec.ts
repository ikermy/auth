import { Test, TestingModule } from '@nestjs/testing';
import { TelegramAuthService } from '../../src/auth/telegram-auth.service';
import { PrismaService } from '../../src/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { RpcException } from '@nestjs/microservices';
import { status } from '@grpc/grpc-js';
import { OracleUsernameService } from '../../src/auth/services/oracle-username.service';
import { OracleIdentityService } from '../../src/auth/services/oracle-identity.service';
import { HttpService } from '@nestjs/axios';
import * as crypto from 'crypto';

jest.mock('crypto', () => ({
  ...jest.requireActual('crypto'),
  createHash: jest.fn(() => ({
    update: jest.fn().mockReturnThis(),
    digest: jest.fn(() => Buffer.from('mock-secret-key')),
  })),
  createHmac: jest.fn(() => ({
    update: jest.fn().mockReturnThis(),
    digest: jest.fn(() => Buffer.from('mock-hash')),
  })),
  randomBytes: jest.fn(() => Buffer.from('mock-random')),
}));

describe('TelegramAuthService', () => {
  let service: TelegramAuthService;
  let prismaService: jest.Mocked<PrismaService>;
  let jwtService: jest.Mocked<JwtService>;
  let configService: jest.Mocked<ConfigService>;

  const mockPrismaService = {
    user: {
      findUnique: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
    },
  } as any;

  const mockJwtService = {
    signAsync: jest.fn(),
  };

  const mockConfigService = {
    get: jest.fn(),
    getOrThrow: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TelegramAuthService,
        {
          provide: PrismaService,
          useValue: mockPrismaService,
        },
        {
          provide: JwtService,
          useValue: mockJwtService,
        },
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
        {
          provide: OracleUsernameService,
          useValue: {
            generateOracleUsername: jest.fn(),
            isValidOracleUsername: jest.fn(),
            normalizeOracleUsername: jest.fn(),
            generateAlternativeOracleUsername: jest.fn(),
          },
        },
        {
          provide: OracleIdentityService,
          useValue: {
            getOracleIdentity: jest.fn(),
            changeOracleUsername: jest.fn(),
            changeOracleNickName: jest.fn(),
            canChangeOracleUsername: jest.fn(),
            suggestUsernameAlternatives: jest.fn(),
            generateUsernameAlternatives: jest.fn(),
          },
        },
        {
          provide: HttpService,
          useValue: {
            get: jest.fn(),
            post: jest.fn(),
            put: jest.fn(),
            delete: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<TelegramAuthService>(TelegramAuthService);
    prismaService = module.get(PrismaService);
    jwtService = module.get(JwtService);
    configService = module.get(ConfigService);

    // Сброс моков
    jest.clearAllMocks();

    // Настройка конфига
    configService.get.mockReturnValue('test-bot-token');
    configService.getOrThrow.mockImplementation((key: string) => {
      if (key === 'JWT_EXPIRES_IN') return '1h';
      if (key === 'JWT_REFRESH_IN') return '7d';
      return 'default-value';
    });
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('validateTelegramAuth', () => {
    const mockAuthData = {
      telegramId: '123456789',
      firstName: 'John',
      lastName: 'Doe',
      username: 'johndoe',
      photoUrl: 'https://t.me/i/userpic/320/photo.jpg',
      authDate: Math.floor(Date.now() / 1000).toString(),
      hash: 'mock-hash',
    };

    it('should validate auth data with correct signature', () => {
      const result = service.validateTelegramAuth(mockAuthData);
      expect(result).toBe(true);
    });

    it('should reject auth data with expired auth date', () => {
      const oldAuthDate = '1000000000'; // Очень старая дата
      const invalidAuthData = { ...mockAuthData, authDate: oldAuthDate };

      const result = service.validateTelegramAuth(invalidAuthData);
      expect(result).toBe(false);
    });

    it('should reject auth data with invalid signature', () => {
      const invalidAuthData = { ...mockAuthData, hash: 'invalid-hash' };

      const result = service.validateTelegramAuth(invalidAuthData);
      expect(result).toBe(false);
    });
  });

  describe('authenticateOrCreateUser', () => {
    const mockAuthData = {
      telegramId: '123456789',
      firstName: 'John',
      lastName: 'Doe',
      username: 'johndoe',
      photoUrl: 'https://t.me/i/userpic/320/photo.jpg',
      authDate: Math.floor(Date.now() / 1000).toString(),
      hash: 'mock-hash',
    };

    const mockUser = {
      id: 'user-id',
      email: 'test@example.com',
      telegramId: '123456789',
      telegramUsername: 'johndoe',
      telegramFirstName: 'John',
      telegramLastName: 'Doe',
      telegramPhotoUrl: 'https://t.me/i/userpic/320/photo.jpg',
      isTelegramVerified: true,
    };

    it('should create new user when user does not exist', async () => {
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(null);
      (prismaService.user.create as jest.Mock).mockResolvedValue(
        mockUser as any,
      );

      const result = await service.authenticateOrCreateUser(mockAuthData);

      expect(result.isNewUser).toBe(true);
      expect(result.user.id).toBe('user-id');
      expect(prismaService.user.create).toHaveBeenCalled();
    });

    it('should update existing user when user exists', async () => {
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(
        mockUser as any,
      );
      (prismaService.user.update as jest.Mock).mockResolvedValue({
        ...mockUser,
        lastLoginAt: new Date(),
      } as any);

      const result = await service.authenticateOrCreateUser(mockAuthData);

      expect(result.isNewUser).toBe(false);
      expect(result.user.id).toBe('user-id');
      expect(prismaService.user.update).toHaveBeenCalled();
    });

    it('should reject invalid auth data', async () => {
      const invalidAuthData = { ...mockAuthData, telegramId: '' };

      await expect(
        service.authenticateOrCreateUser(invalidAuthData),
      ).rejects.toThrow(RpcException);
    });
  });

  describe('generateTokens', () => {
    it('should generate access and refresh tokens', async () => {
      jwtService.signAsync.mockResolvedValue('mock-token');

      const result = await service.generateTokens(
        'user-id',
        'test@example.com',
      );

      expect(result.accessToken).toBe('mock-token');
      expect(result.refreshToken).toBe('mock-token');
      expect(jwtService.signAsync).toHaveBeenCalledTimes(2);
    });
  });

  describe('linkTelegramToExistingAccount', () => {
    const mockAuthData = {
      telegramId: '123456789',
      firstName: 'John',
      lastName: 'Doe',
      username: 'johndoe',
      photoUrl: 'https://t.me/i/userpic/320/photo.jpg',
      authDate: Math.floor(Date.now() / 1000).toString(),
      hash: 'mock-hash',
    };

    it('should link telegram account to existing user', async () => {
      // Первый вызов: проверка, не занят ли Telegram ID
      (prismaService.user.findUnique as jest.Mock)
        .mockResolvedValueOnce(null) // Telegram ID не занят
        .mockResolvedValueOnce({ id: 'user-id' } as any); // Пользователь существует
      (prismaService.user.update as jest.Mock).mockResolvedValue({
        id: 'user-id',
      } as any);

      const result = await service.linkTelegramToExistingAccount(
        'user-id',
        mockAuthData,
      );

      expect(result).toBe(true);
      expect(prismaService.user.update).toHaveBeenCalled();
    });

    it('should reject when telegram account is already linked to another user', async () => {
      const existingUser = { id: 'other-user-id' };
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(
        existingUser as any,
      );

      await expect(
        service.linkTelegramToExistingAccount('user-id', mockAuthData),
      ).rejects.toThrow(RpcException);
    });

    it('should reject when user does not exist', async () => {
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(null);

      await expect(
        service.linkTelegramToExistingAccount('user-id', mockAuthData),
      ).rejects.toThrow(RpcException);
    });
  });

  describe('getTelegramUserInfo', () => {
    it('should return telegram user info when user exists', async () => {
      const mockUser = {
        telegramId: '123456789',
        telegramFirstName: 'John',
        telegramLastName: 'Doe',
        telegramUsername: 'johndoe',
        telegramPhotoUrl: 'https://t.me/i/userpic/320/photo.jpg',
      };

      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(
        mockUser as any,
      );

      const result = await service.getTelegramUserInfo('123456789');

      expect(result).toEqual({
        id: '123456789',
        first_name: 'John',
        last_name: 'Doe',
        username: 'johndoe',
        photo_url: 'https://t.me/i/userpic/320/photo.jpg',
      });
    });

    it('should return null when user does not exist', async () => {
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(null);

      const result = await service.getTelegramUserInfo('123456789');

      expect(result).toBeNull();
    });
  });

  describe('botToken configuration', () => {
    it('should throw error when TELEGRAM_BOT_TOKEN is not configured', () => {
      configService.get.mockReturnValue(null);

      expect(() => {
        // Доступ к botToken через приватное свойство
        (service as any).botToken;
      }).toThrow('TELEGRAM_BOT_TOKEN is not configured');
    });

    it('should return bot token when configured', () => {
      configService.get.mockReturnValue('valid-bot-token');

      const result = (service as any).botToken;
      expect(result).toBe('valid-bot-token');
    });
  });
});
