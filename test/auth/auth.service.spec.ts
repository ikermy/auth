import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from '../../src/auth/auth.service';
import { PrismaService } from '../../src/prisma.service';
import { EnhancedJwtService } from '../../src/security/services/enhanced-jwt.service';
import { SecurityLoggerService } from '../../src/security/security-logger.service';
import * as bcrypt from 'bcrypt';

jest.mock('bcrypt');

describe('AuthService', () => {
  let service: AuthService;
  let prismaService: PrismaService;
  let enhancedJwtService: EnhancedJwtService;
  let securityLogger: SecurityLoggerService;

  const mockUser = {
    id: '1',
    email: 'test@example.com',
    password: '$2b$10$hashedpassword',
    isActive: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockTokens = {
    accessToken: 'mock.access.token',
    refreshToken: 'mock.refresh.token',
    accessTokenId: 'access-123',
    refreshTokenId: 'refresh-123',
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: PrismaService,
          useValue: {
            user: {
              create: jest.fn(),
              findUnique: jest.fn(),
              update: jest.fn(),
            },
            loginAttempt: {
              create: jest.fn(),
            },
          },
        },
        {
          provide: EnhancedJwtService,
          useValue: {
            generateTokens: jest.fn(),
            verifyToken: jest.fn(),
            revokeToken: jest.fn(),
            revokeAllUserTokens: jest.fn(),
          },
        },
        {
          provide: SecurityLoggerService,
          useValue: {
            logSecurityEvent: jest.fn(),
            logSecurityError: jest.fn(),
            logDatabase: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    prismaService = module.get<PrismaService>(PrismaService);
    enhancedJwtService = module.get<EnhancedJwtService>(EnhancedJwtService);
    securityLogger = module.get<SecurityLoggerService>(SecurityLoggerService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('register', () => {
    it('should register new user successfully', async () => {
      const registerRequest = {
        email: 'newuser@example.com',
        password: 'StrongPass123!',
      };

      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(null);
      (bcrypt.hash as jest.Mock).mockResolvedValue('$2b$10$hashedpassword');
      (prismaService.user.create as jest.Mock).mockResolvedValue(mockUser);

      const result = await service.register(registerRequest);

      expect(result.success).toBe(true);
      expect(result.user).toEqual(mockUser);
      expect(bcrypt.hash).toHaveBeenCalledWith('StrongPass123!', 10);
      expect(securityLogger.logDatabase).toHaveBeenCalledWith(
        'USER_CREATED',
        'New user registered: newuser@example.com',
      );
    });

    it('should fail registration if user already exists', async () => {
      const registerRequest = {
        email: 'existing@example.com',
        password: 'StrongPass123!',
      };

      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(mockUser);

      const result = await service.register(registerRequest);

      expect(result.success).toBe(false);
      expect(result.error).toBe('User already exists');
    });

    it('should handle database errors during registration', async () => {
      const registerRequest = {
        email: 'newuser@example.com',
        password: 'StrongPass123!',
      };

      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(null);
      (bcrypt.hash as jest.Mock).mockResolvedValue('$2b$10$hashedpassword');
      (prismaService.user.create as jest.Mock).mockRejectedValue(
        new Error('Database error'),
      );

      const result = await service.register(registerRequest);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Registration failed');
      expect(securityLogger.logSecurityError).toHaveBeenCalledWith(
        'REGISTRATION_FAILED',
        expect.stringContaining('Database error'),
      );
    });
  });

  describe('login', () => {
    it('should login user successfully', async () => {
      const loginRequest = {
        email: 'test@example.com',
        password: 'password123',
      };

      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (bcrypt.compare as jest.Mock).mockResolvedValue(true);
      (enhancedJwtService.generateTokens as jest.Mock).mockResolvedValue(
        mockTokens,
      );
      (prismaService.loginAttempt.create as jest.Mock).mockResolvedValue({});

      const result = await service.login(loginRequest);

      expect(result.success).toBe(true);
      expect(result.accessToken).toBe(mockTokens.accessToken);
      expect(result.refreshToken).toBe(mockTokens.refreshToken);
      expect(securityLogger.logSecurityEvent).toHaveBeenCalledWith(
        'LOGIN_SUCCESS',
        'User logged in: test@example.com',
      );
    });

    it('should fail login with invalid credentials', async () => {
      const loginRequest = {
        email: 'test@example.com',
        password: 'wrongpassword',
      };

      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);
      (prismaService.loginAttempt.create as jest.Mock).mockResolvedValue({});

      const result = await service.login(loginRequest);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid credentials');
      expect(securityLogger.logSecurityError).toHaveBeenCalledWith(
        'LOGIN_FAILED',
        'Invalid credentials for: test@example.com',
      );
    });

    it('should fail login for non-existent user', async () => {
      const loginRequest = {
        email: 'nonexistent@example.com',
        password: 'password123',
      };

      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(null);
      (prismaService.loginAttempt.create as jest.Mock).mockResolvedValue({});

      const result = await service.login(loginRequest);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid credentials');
    });

    it('should fail login for inactive user', async () => {
      const inactiveUser = { ...mockUser, isActive: false };
      const loginRequest = {
        email: 'inactive@example.com',
        password: 'password123',
      };

      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(
        inactiveUser,
      );
      (prismaService.loginAttempt.create as jest.Mock).mockResolvedValue({});

      const result = await service.login(loginRequest);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Account is disabled');
    });
  });

  describe('refreshToken', () => {
    it('should refresh token successfully', async () => {
      const refreshRequest = {
        refreshToken: 'valid.refresh.token',
      };

      const mockPayload = {
        sub: '1',
        email: 'test@example.com',
        type: 'refresh',
      };

      (enhancedJwtService.verifyToken as jest.Mock).mockResolvedValue(
        mockPayload,
      );
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (enhancedJwtService.generateTokens as jest.Mock).mockResolvedValue(
        mockTokens,
      );

      const result = await service.refreshToken(refreshRequest);

      expect(result.success).toBe(true);
      expect(result.accessToken).toBe(mockTokens.accessToken);
      expect(result.refreshToken).toBe(mockTokens.refreshToken);
    });

    it('should fail refresh with invalid token', async () => {
      const refreshRequest = {
        refreshToken: 'invalid.token',
      };

      (enhancedJwtService.verifyToken as jest.Mock).mockRejectedValue(
        new Error('Invalid token'),
      );

      const result = await service.refreshToken(refreshRequest);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid refresh token');
    });

    it('should fail refresh for non-existent user', async () => {
      const refreshRequest = {
        refreshToken: 'valid.refresh.token',
      };

      const mockPayload = {
        sub: '1',
        email: 'test@example.com',
        type: 'refresh',
      };

      (enhancedJwtService.verifyToken as jest.Mock).mockResolvedValue(
        mockPayload,
      );
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(null);

      const result = await service.refreshToken(refreshRequest);

      expect(result.success).toBe(false);
      expect(result.error).toBe('User not found');
    });
  });

  describe('logout', () => {
    it('should logout user successfully', async () => {
      const logoutRequest = {
        accessToken: 'valid.access.token',
      };

      const mockPayload = {
        sub: '1',
        jti: 'token-123',
        type: 'access',
      };

      (enhancedJwtService.verifyToken as jest.Mock).mockResolvedValue(
        mockPayload,
      );
      (enhancedJwtService.revokeToken as jest.Mock).mockResolvedValue(
        undefined,
      );

      const result = await service.logout(logoutRequest);

      expect(result.success).toBe(true);
      expect(enhancedJwtService.revokeToken).toHaveBeenCalledWith('token-123');
      expect(securityLogger.logSecurityEvent).toHaveBeenCalledWith(
        'LOGOUT_SUCCESS',
        'User logged out: 1',
      );
    });

    it('should fail logout with invalid token', async () => {
      const logoutRequest = {
        accessToken: 'invalid.token',
      };

      (enhancedJwtService.verifyToken as jest.Mock).mockRejectedValue(
        new Error('Invalid token'),
      );

      const result = await service.logout(logoutRequest);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid access token');
    });
  });

  describe('validateToken', () => {
    it('should validate token successfully', async () => {
      const token = 'valid.token';
      const mockPayload = {
        sub: '1',
        email: 'test@example.com',
        type: 'access',
      };

      (enhancedJwtService.verifyToken as jest.Mock).mockResolvedValue(
        mockPayload,
      );
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(mockUser);

      const result = await service.validateToken(token);

      expect(result.valid).toBe(true);
      expect(result.user).toEqual(mockUser);
    });

    it('should fail validation with invalid token', async () => {
      const token = 'invalid.token';

      (enhancedJwtService.verifyToken as jest.Mock).mockRejectedValue(
        new Error('Invalid token'),
      );

      const result = await service.validateToken(token);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid token');
    });

    it('should fail validation for non-existent user', async () => {
      const token = 'valid.token';
      const mockPayload = {
        sub: '1',
        email: 'test@example.com',
        type: 'access',
      };

      (enhancedJwtService.verifyToken as jest.Mock).mockResolvedValue(
        mockPayload,
      );
      (prismaService.user.findUnique as jest.Mock).mockResolvedValue(null);

      const result = await service.validateToken(token);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('User not found');
    });
  });
});
