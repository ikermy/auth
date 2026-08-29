import { Test, TestingModule } from '@nestjs/testing';
import { SecureAuthService } from '../../src/security/services/secure-auth.service';
import { PrismaService } from '../../src/prisma.service';
import * as bcrypt from 'bcrypt';

jest.mock('bcrypt');

describe('SecureAuthService', () => {
  let service: SecureAuthService;
  let prismaService: PrismaService;

  const mockUser = {
    id: '1',
    email: 'test@example.com',
    password: '$2b$10$hashedpassword',
    isActive: true,
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SecureAuthService,
        {
          provide: PrismaService,
          useValue: {
            user: {
              findUnique: jest.fn(),
            },
          },
        },
      ],
    }).compile();

    service = module.get<SecureAuthService>(SecureAuthService);
    prismaService = module.get<PrismaService>(PrismaService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('authenticateUser', () => {
    it('should authenticate user with correct credentials', async () => {
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (bcrypt.compare as jest.Mock).mockResolvedValue(true);

      const result = await service.authenticateUser(
        'test@example.com',
        'password123',
      );

      expect(result.success).toBe(true);
      expect(result.user).toEqual(mockUser);
    });

    it('should fail authentication with incorrect password', async () => {
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      const result = await service.authenticateUser(
        'test@example.com',
        'wrongpassword',
      );

      expect(result.success).toBe(false);
      expect(result.user).toBeUndefined();
    });

    it('should fail authentication for non-existent user', async () => {
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(null);

      const result = await service.authenticateUser(
        'nonexistent@example.com',
        'password123',
      );

      expect(result.success).toBe(false);
      expect(result.user).toBeUndefined();
    });

    it('should fail authentication for inactive user', async () => {
      const inactiveUser = { ...mockUser, isActive: false };
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(
        inactiveUser,
      );

      const result = await service.authenticateUser(
        'test@example.com',
        'password123',
      );

      expect(result.success).toBe(false);
      expect(result.user).toBeUndefined();
    });

    it('should have consistent timing for security', async () => {
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      const startTime = Date.now();
      await service.authenticateUser('test@example.com', 'wrongpassword');
      const endTime = Date.now();

      const duration = endTime - startTime;
      expect(duration).toBeGreaterThan(50); // Should take some time for security
    });
  });

  describe('validatePasswordStrength', () => {
    it('should validate strong password', () => {
      const result = service.validatePasswordStrength('StrongPass123!');

      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject weak password', () => {
      const result = service.validatePasswordStrength('weak');

      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should reject password without uppercase', () => {
      const result = service.validatePasswordStrength('password123!');

      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'Password must contain at least one uppercase letter',
      );
    });

    it('should reject password without lowercase', () => {
      const result = service.validatePasswordStrength('PASSWORD123!');

      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'Password must contain at least one lowercase letter',
      );
    });

    it('should reject password without numbers', () => {
      const result = service.validatePasswordStrength('Password!');

      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'Password must contain at least one number',
      );
    });

    it('should reject password without special characters', () => {
      const result = service.validatePasswordStrength('Password123');

      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'Password must contain at least one special character',
      );
    });

    it('should reject password that is too short', () => {
      const result = service.validatePasswordStrength('Pass1!');

      expect(result.valid).toBe(false);
      expect(result.errors).toContain(
        'Password must be at least 12 characters long',
      );
    });
  });
});
