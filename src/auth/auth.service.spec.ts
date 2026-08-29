import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { PrismaService } from '../prisma.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { EncryptionService } from '../security/services/encryption.service';
import { OracleUsernameService } from './services/oracle-username.service';
import { OracleIdentityService } from './services/oracle-identity.service';

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
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
