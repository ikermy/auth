import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { PrismaService } from '../prisma.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { EncryptionService } from '../security/services/encryption.service';
import { EnhancedJwtService } from '../security/services/enhanced-jwt.service';
import { SessionService } from '../security/services/session.service';
import { UsernameService } from './services/username.service';
import { UserIdentityService } from './services/user-identity.service';

describe('AuthService', () => {
  let service: AuthService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: PrismaService,
          useValue: {
            user: {
              findUnique: jest.fn(),
              create: jest.fn(),
            },
          },
        },
        {
          provide: JwtService,
          useValue: {
            sign: jest.fn(),
          },
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn(),
          },
        },
        {
          provide: EncryptionService,
          useValue: {
            encrypt: jest.fn(),
            decrypt: jest.fn(),
          },
        },
        {
          provide: UsernameService,
          useValue: {
            generateUsername: jest.fn(),
            isValidUserUsername: jest.fn(),
            normalizeUserUsername: jest.fn(),
            generateAlternativeUsername: jest.fn(),
          },
        },
        {
          provide: UserIdentityService,
          useValue: {
            getUserIdentity: jest.fn(),
            changeUsername: jest.fn(),
            changeNickname: jest.fn(),
            canChangeUsername: jest.fn(),
            suggestUsernameAlternatives: jest.fn(),
            generateUsernameAlternatives: jest.fn(),
          },
        },
        {
          provide: EnhancedJwtService,
          useValue: {
            generateTokens: jest.fn(),
            verifyToken: jest.fn(),
          },
        },
        {
          provide: SessionService,
          useValue: {
            create: jest.fn(),
            findByRefreshJti: jest.fn(),
            deactivate: jest.fn(),
            deactivateAll: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
