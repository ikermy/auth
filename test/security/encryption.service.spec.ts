import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { EncryptionService } from '../../src/security/services/encryption.service';
import { SecurityLoggerService } from '../../src/security/security-logger.service';

describe('EncryptionService', () => {
  let service: EncryptionService;
  let configService: ConfigService;
  let securityLogger: SecurityLoggerService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        EncryptionService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string, defaultValue?: any) => {
              const config: Record<string, any> = {
                ENCRYPTION_KEY:
                  'test-encryption-key-32-chars-long-12345678901234567890123456789012',
                ENCRYPTION_ALGORITHM: 'aes-256-gcm',
              };
              return config[key] || defaultValue;
            }),
          },
        },
        {
          provide: SecurityLoggerService,
          useValue: {
            logSecurityError: jest.fn(),
            logSuccess: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<EncryptionService>(EncryptionService);
    configService = module.get<ConfigService>(ConfigService);
    securityLogger = module.get<SecurityLoggerService>(SecurityLoggerService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('encrypt and decrypt', () => {
    it('should encrypt and decrypt data correctly', () => {
      const originalData = 'sensitive data to encrypt';

      const encrypted = service.encrypt(originalData);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe(originalData);
      expect(encrypted).not.toBe(originalData);
    });

    it('should encrypt different data differently', () => {
      const data1 = 'data1';
      const data2 = 'data2';

      const encrypted1 = service.encrypt(data1);
      const encrypted2 = service.encrypt(data2);

      expect(encrypted1).not.toBe(encrypted2);
    });

    it('should encrypt same data differently each time', () => {
      const data = 'same data';

      const encrypted1 = service.encrypt(data);
      const encrypted2 = service.encrypt(data);

      expect(encrypted1).not.toBe(encrypted2);
    });

    it('should throw error when decrypting invalid data', () => {
      expect(() => {
        service.decrypt('invalid-encrypted-data');
      }).toThrow();
    });
  });

  describe('hashWithSalt', () => {
    it('should hash data with salt', () => {
      const data = 'data to hash';
      const salt = 'test-salt';

      const hashed = service.hashWithSalt(data, salt);

      expect(hashed).toBeDefined();
      expect(hashed).not.toBe(data);
    });

    it('should produce different hashes for different salts', () => {
      const data = 'same data';
      const salt1 = 'salt1';
      const salt2 = 'salt2';

      const hash1 = service.hashWithSalt(data, salt1);
      const hash2 = service.hashWithSalt(data, salt2);

      expect(hash1).not.toBe(hash2);
    });
  });

  describe('verifyHash', () => {
    it('should verify correct hash', () => {
      const data = 'data to verify';
      const salt = 'test-salt';
      const hashed = service.hashWithSalt(data, salt);

      const isValid = service.verifyHash(data, hashed.hash, hashed.salt);

      expect(isValid).toBe(true);
    });

    it('should reject incorrect hash', () => {
      const data = 'data to verify';
      const salt = 'test-salt';
      const hashed = service.hashWithSalt(data, salt);

      const isValid = service.verifyHash('wrong data', salt, hashed.hash);

      expect(isValid).toBe(false);
    });
  });

  describe('generateSecureToken', () => {
    it('should generate secure token', () => {
      const token = service.generateSecureToken();

      expect(token).toBeDefined();
      expect(token.length).toBeGreaterThan(32);
    });

    it('should generate different tokens each time', () => {
      const token1 = service.generateSecureToken();
      const token2 = service.generateSecureToken();

      expect(token1).not.toBe(token2);
    });
  });

  describe('encryptJwtPayload and decryptJwtPayload', () => {
    it('should encrypt and decrypt JWT payload', () => {
      const payload = {
        sub: '1',
        email: 'test@example.com',
        iat: Date.now(),
        exp: Date.now() + 3600000,
      };

      const encrypted = service.encryptJwtPayload(payload);
      const decrypted = service.decryptJwtPayload(encrypted);

      expect(decrypted).toEqual(payload);
      expect(encrypted).not.toEqual(payload);
    });
  });

  describe('verifyDataIntegrity', () => {
    it('should verify data integrity', () => {
      const data = 'data to verify';
      const signature = service.signData(data);

      const isValid = service.verifyDataIntegrity(data, signature);

      expect(isValid).toBe(true);
    });

    it('should reject tampered data', () => {
      const data = 'original data';
      const signature = service.signData(data);

      const isValid = service.verifyDataIntegrity('tampered data', signature);

      expect(isValid).toBe(false);
    });
  });
});
