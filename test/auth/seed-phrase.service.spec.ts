import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from '../../src/auth/auth.service';
import { PrismaService } from '../../src/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { EncryptionService } from '../../src/security/services/encryption.service';
import { RpcException } from '@nestjs/microservices';
import { status } from '@grpc/grpc-js';
import * as bcrypt from 'bcrypt';

describe('AuthService - Seed Phrase', () => {
  let service: AuthService;
  let prismaService: PrismaService;
  let jwtService: JwtService;
  let configService: ConfigService;
  let encryptionService: EncryptionService;

  const mockUser = {
    id: 'test-user-id',
    email: 'test@example.com',
    seedPhraseEnabled: false,
    seedPhraseHash: null,
    seedPhraseSalt: null,
    seedPhraseAttempts: 0,
    seedPhraseLockedUntil: null,
  };

  const mockPrismaService = {
    user: {
      findUnique: jest.fn(),
      update: jest.fn(),
    },
  };

  const mockJwtService = {
    signAsync: jest.fn(),
    verifyAsync: jest.fn(),
  };

  const mockConfigService = {
    getOrThrow: jest.fn().mockReturnValue('test-secret'),
  };

  const mockEncryptionService = {
    encrypt: jest.fn().mockReturnValue('encrypted-token'),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
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
          provide: EncryptionService,
          useValue: mockEncryptionService,
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    prismaService = module.get<PrismaService>(PrismaService);
    jwtService = module.get<JwtService>(JwtService);
    configService = module.get<ConfigService>(ConfigService);
    encryptionService = module.get<EncryptionService>(EncryptionService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('enableSeedPhrase', () => {
    it('should enable seed phrase successfully', async () => {
      const request = {
        userId: 'test-user-id',
        seedPhrase:
          'abandon ability able about above absent absorb abstract absurd abuse access accident',
      };

      mockPrismaService.user.findUnique.mockResolvedValue(mockUser);
      mockPrismaService.user.update.mockResolvedValue({
        ...mockUser,
        seedPhraseEnabled: true,
      });

      const result = await service.enableSeedPhrase(request);

      expect(result.success).toBe(true);
      expect(result.message).toBe('Seed phrase enabled successfully');
      expect(mockPrismaService.user.update).toHaveBeenCalledWith({
        where: { id: request.userId },
        data: expect.objectContaining({
          seedPhraseEnabled: true,
          seedPhraseHash: expect.any(String),
          seedPhraseSalt: expect.any(String),
          seedPhraseAttempts: 0,
          seedPhraseLockedUntil: null,
        }),
      });
    });

    it('should throw error for insufficient words', async () => {
      const request = {
        userId: 'test-user-id',
        seedPhrase: 'word1 word2 word3',
      };

      await expect(service.enableSeedPhrase(request)).rejects.toThrow(
        RpcException,
      );
    });

    it('should throw error for invalid format (numbers)', async () => {
      const request = {
        userId: 'test-user-id',
        seedPhrase:
          'word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12',
      };

      mockPrismaService.user.findUnique.mockResolvedValue(mockUser);

      await expect(service.enableSeedPhrase(request)).rejects.toThrow(
        RpcException,
      );
    });

    it('should throw error for invalid format (special characters)', async () => {
      const request = {
        userId: 'test-user-id',
        seedPhrase:
          'word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12!',
      };

      mockPrismaService.user.findUnique.mockResolvedValue(mockUser);

      await expect(service.enableSeedPhrase(request)).rejects.toThrow(
        RpcException,
      );
    });

    it('should throw error for already enabled seed phrase', async () => {
      const request = {
        userId: 'test-user-id',
        seedPhrase:
          'abandon ability able about above absent absorb abstract absurd abuse access accident',
      };

      const userWithSeed = { ...mockUser, seedPhraseEnabled: true };
      mockPrismaService.user.findUnique.mockResolvedValue(userWithSeed);

      await expect(service.enableSeedPhrase(request)).rejects.toThrow(
        RpcException,
      );
    });

    it('should throw error for invalid user ID', async () => {
      const request = {
        userId: '',
        seedPhrase:
          'abandon ability able about above absent absorb abstract absurd abuse access accident',
      };

      await expect(service.enableSeedPhrase(request)).rejects.toThrow(
        RpcException,
      );
    });

    it('should throw error for user not found', async () => {
      const request = {
        userId: 'test-user-id',
        seedPhrase:
          'abandon ability able about above absent absorb abstract absurd abuse access accident',
      };

      mockPrismaService.user.findUnique.mockResolvedValue(null);

      await expect(service.enableSeedPhrase(request)).rejects.toThrow(
        RpcException,
      );
    });
  });

  describe('verifySeedPhrase', () => {
    it('should verify seed phrase successfully', async () => {
      const request = {
        userId: 'test-user-id',
        seedPhrase:
          'abandon ability able about above absent absorb abstract absurd abuse access accident',
      };

      const hashedSeedPhrase = await bcrypt.hash(request.seedPhrase, 14);
      const userWithSeed = {
        ...mockUser,
        seedPhraseEnabled: true,
        seedPhraseHash: hashedSeedPhrase,
      };

      mockPrismaService.user.findUnique.mockResolvedValue(userWithSeed);
      mockPrismaService.user.update.mockResolvedValue(userWithSeed);
      mockJwtService.signAsync.mockResolvedValue('user-token');

      const result = await service.verifySeedPhrase(request);

      expect(result.success).toBe(true);
      expect(result.message).toBe('Seed phrase verified successfully');
      expect(result.requestId).toBeDefined();
    });

    it('should throw error for invalid seed phrase', async () => {
      const request = {
        userId: 'test-user-id',
        seedPhrase: 'wrong seed phrase',
      };

      const hashedSeedPhrase = await bcrypt.hash('correct seed phrase', 14);
      const userWithSeed = {
        ...mockUser,
        seedPhraseEnabled: true,
        seedPhraseHash: hashedSeedPhrase,
        seedPhraseAttempts: 0,
      };

      mockPrismaService.user.findUnique.mockResolvedValue(userWithSeed);
      mockPrismaService.user.update.mockResolvedValue(userWithSeed);

      await expect(service.verifySeedPhrase(request)).rejects.toThrow(
        RpcException,
      );
    });

    it('should throw error for disabled seed phrase', async () => {
      const request = {
        userId: 'test-user-id',
        seedPhrase:
          'abandon ability able about above absent absorb abstract absurd abuse access accident',
      };

      mockPrismaService.user.findUnique.mockResolvedValue(mockUser);

      await expect(service.verifySeedPhrase(request)).rejects.toThrow(
        RpcException,
      );
    });

    it('should lock account after too many attempts', async () => {
      const request = {
        userId: 'test-user-id',
        seedPhrase: 'wrong seed phrase',
      };

      const hashedSeedPhrase = await bcrypt.hash('correct seed phrase', 14);
      const userWithSeed = {
        ...mockUser,
        seedPhraseEnabled: true,
        seedPhraseHash: hashedSeedPhrase,
        seedPhraseAttempts: 4,
      };

      mockPrismaService.user.findUnique.mockResolvedValue(userWithSeed);
      mockPrismaService.user.update.mockResolvedValue(userWithSeed);

      await expect(service.verifySeedPhrase(request)).rejects.toThrow(
        RpcException,
      );
    });
  });

  describe('disableSeedPhrase', () => {
    it('should disable seed phrase successfully', async () => {
      const request = {
        userId: 'test-user-id',
        seedPhrase:
          'abandon ability able about above absent absorb abstract absurd abuse access accident',
      };

      const hashedSeedPhrase = await bcrypt.hash(request.seedPhrase, 14);
      const userWithSeed = {
        ...mockUser,
        seedPhraseEnabled: true,
        seedPhraseHash: hashedSeedPhrase,
      };

      mockPrismaService.user.findUnique.mockResolvedValue(userWithSeed);
      mockPrismaService.user.update.mockResolvedValue({
        ...userWithSeed,
        seedPhraseEnabled: false,
      });

      const result = await service.disableSeedPhrase(request);

      expect(result.success).toBe(true);
      expect(result.message).toBe('Seed phrase disabled successfully');
    });

    it('should throw error for invalid seed phrase', async () => {
      const request = {
        userId: 'test-user-id',
        seedPhrase: 'wrong seed phrase',
      };

      const hashedSeedPhrase = await bcrypt.hash('correct seed phrase', 14);
      const userWithSeed = {
        ...mockUser,
        seedPhraseEnabled: true,
        seedPhraseHash: hashedSeedPhrase,
      };

      mockPrismaService.user.findUnique.mockResolvedValue(userWithSeed);

      await expect(service.disableSeedPhrase(request)).rejects.toThrow(
        RpcException,
      );
    });
  });

  describe('getSeedPhraseStatus', () => {
    it('should return seed phrase status', async () => {
      const request = {
        userId: 'test-user-id',
      };

      const userWithSeed = {
        ...mockUser,
        seedPhraseEnabled: true,
        seedPhraseAttempts: 2,
        seedPhraseLockedUntil: null,
      };

      mockPrismaService.user.findUnique.mockResolvedValue(userWithSeed);

      const result = await service.getSeedPhraseStatus(request);

      expect(result.enabled).toBe(true);
      expect(result.attempts).toBe(2);
      expect(result.lockedUntil).toBe('');
      expect(result.message).toBe('Seed phrase is enabled');
    });

    it('should return locked status', async () => {
      const request = {
        userId: 'test-user-id',
      };

      const lockedUntil = new Date(Date.now() + 15 * 60 * 1000);
      const userWithSeed = {
        ...mockUser,
        seedPhraseEnabled: true,
        seedPhraseAttempts: 5,
        seedPhraseLockedUntil: lockedUntil,
      };

      mockPrismaService.user.findUnique.mockResolvedValue(userWithSeed);

      const result = await service.getSeedPhraseStatus(request);

      expect(result.enabled).toBe(true);
      expect(result.attempts).toBe(5);
      expect(result.lockedUntil).toBe(lockedUntil.toISOString());
    });
  });
});
