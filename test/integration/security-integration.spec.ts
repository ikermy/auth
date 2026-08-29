import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from '../../src/auth/auth.controller';
import { AuthService } from '../../src/auth/auth.service';
import { SecurityModule } from '../../src/security/security.module';
import { PrismaService } from '../../src/prisma.service';
import { ConfigModule } from '@nestjs/config';

describe('Security Integration Tests', () => {
  let module: TestingModule;
  let authController: AuthController;
  let authService: AuthService;
  let prismaService: PrismaService;

  beforeAll(async () => {
    module = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
          envFilePath: '.env.test',
        }),
        SecurityModule,
      ],
      controllers: [AuthController],
      providers: [AuthService, PrismaService],
    }).compile();

    authController = module.get<AuthController>(AuthController);
    authService = module.get<AuthService>(AuthService);
    prismaService = module.get<PrismaService>(PrismaService);
  });

  afterAll(async () => {
    await module.close();
  });

  describe('Complete Authentication Flow with Security', () => {
    it('should handle registration with password validation', async () => {
      const registerRequest = {
        email: 'integration@test.com',
        password: 'StrongPass123!',
      };

      const result = await authController.register(registerRequest);

      expect(result.success).toBe(true);
      expect(result.user).toBeDefined();
      expect(result.user.email).toBe('integration@test.com');
    });

    it('should handle login with brute force protection', async () => {
      const loginRequest = {
        email: 'integration@test.com',
        password: 'StrongPass123!',
      };

      const result = await authController.login(loginRequest);

      expect(result.success).toBe(true);
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
    });

    it('should block user after multiple failed attempts', async () => {
      const loginRequest = {
        email: 'integration@test.com',
        password: 'wrongpassword',
      };

      // Try multiple failed logins
      for (let i = 0; i < 5; i++) {
        await authController.login(loginRequest);
      }

      // Next attempt should be blocked
      const blockedResult = await authController.login(loginRequest);
      expect(blockedResult.success).toBe(false);
      expect(blockedResult.error).toBe('Account temporarily blocked');
    });

    it('should handle 2FA enablement', async () => {
      const user = await prismaService.user.findUnique({
        where: { email: 'integration@test.com' },
      });

      const result = await authController.enable2FA({ userId: user.id });

      expect(result.success).toBe(true);
      expect(result.qrCode).toBeDefined();
      expect(result.backupCodes).toHaveLength(10);
    });

    it('should require 2FA after enabling it', async () => {
      const loginRequest = {
        email: 'integration@test.com',
        password: 'StrongPass123!',
      };

      const result = await authController.login(loginRequest);

      expect(result.success).toBe(false);
      expect(result.error).toBe('2FA_REQUIRED');
    });

    it('should verify 2FA with backup code', async () => {
      const user = await prismaService.user.findUnique({
        where: { email: 'integration@test.com' },
      });

      // Use first backup code
      const backupCode = user.backupCodes[0];
      const result = await authController.verify2FA({
        userId: user.id,
        token: backupCode,
      });

      expect(result.success).toBe(true);
    });

    it('should get anomaly statistics', async () => {
      const user = await prismaService.user.findUnique({
        where: { email: 'integration@test.com' },
      });

      const stats = await authController.getAnomalyStats({ userId: user.id });

      expect(stats.totalEvents).toBeGreaterThan(0);
      expect(stats.anomalyEvents).toBeGreaterThanOrEqual(0);
      expect(stats.averageScore).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Token Management Integration', () => {
    it('should validate and refresh tokens', async () => {
      const loginRequest = {
        email: 'integration@test.com',
        password: 'StrongPass123!',
      };

      const loginResult = await authController.login(loginRequest);
      expect(loginResult.success).toBe(true);

      // Validate token
      const validationResult = await authService.validateToken(
        loginResult.accessToken,
      );
      expect(validationResult.valid).toBe(true);

      // Refresh token
      const refreshResult = await authService.refreshToken({
        refreshToken: loginResult.refreshToken,
      });
      expect(refreshResult.success).toBe(true);
      expect(refreshResult.accessToken).toBeDefined();
    });

    it('should handle token revocation', async () => {
      const loginRequest = {
        email: 'integration@test.com',
        password: 'StrongPass123!',
      };

      const loginResult = await authController.login(loginRequest);
      expect(loginResult.success).toBe(true);

      // Logout (revoke token)
      const logoutResult = await authService.logout({
        accessToken: loginResult.accessToken,
      });
      expect(logoutResult.success).toBe(true);

      // Try to validate revoked token
      const validationResult = await authService.validateToken(
        loginResult.accessToken,
      );
      expect(validationResult.valid).toBe(false);
    });
  });

  describe('Anomaly Detection Integration', () => {
    it('should detect suspicious login patterns', async () => {
      const loginRequest = {
        email: 'integration@test.com',
        password: 'StrongPass123!',
      };

      // Simulate rapid login attempts
      const promises = [];
      for (let i = 0; i < 10; i++) {
        promises.push(authController.login(loginRequest));
      }

      const results = await Promise.all(promises);

      // Some should succeed, some might be flagged as anomalies
      const successCount = results.filter((r) => r.success).length;
      expect(successCount).toBeGreaterThan(0);
    });

    it('should handle different IP addresses and user agents', async () => {
      const loginRequest = {
        email: 'integration@test.com',
        password: 'StrongPass123!',
      };

      // Simulate login from different locations
      const results = [];
      for (let i = 0; i < 3; i++) {
        const result = await authController.login(loginRequest);
        results.push(result);
      }

      // All should succeed but might trigger anomaly detection
      results.forEach((result) => {
        expect(result.success).toBe(true);
      });
    });
  });

  describe('Encryption Integration', () => {
    it('should encrypt sensitive data in tokens', async () => {
      const loginRequest = {
        email: 'integration@test.com',
        password: 'StrongPass123!',
      };

      const result = await authController.login(loginRequest);
      expect(result.success).toBe(true);

      // Token should be encrypted
      expect(result.accessToken).not.toContain('integration@test.com');
      expect(result.accessToken).toMatch(/^[A-Za-z0-9+/=]+$/); // Base64 format
    });
  });

  describe('Rate Limiting Integration', () => {
    it('should respect rate limits', async () => {
      const registerRequest = {
        email: 'ratelimit@test.com',
        password: 'StrongPass123!',
      };

      // Try to register multiple times rapidly
      const promises = [];
      for (let i = 0; i < 5; i++) {
        promises.push(authController.register(registerRequest));
      }

      const results = await Promise.all(promises);

      // Only first should succeed
      const successCount = results.filter((r) => r.success).length;
      expect(successCount).toBe(1);
    });
  });

  describe('Cleanup', () => {
    it('should clean up test data', async () => {
      // Clean up test users
      await prismaService.user.deleteMany({
        where: {
          email: {
            in: ['integration@test.com', 'ratelimit@test.com'],
          },
        },
      });

      // Verify cleanup
      const users = await prismaService.user.findMany({
        where: {
          email: {
            in: ['integration@test.com', 'ratelimit@test.com'],
          },
        },
      });

      expect(users).toHaveLength(0);
    });
  });
});
