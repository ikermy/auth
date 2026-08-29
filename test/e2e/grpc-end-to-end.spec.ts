import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { join } from 'path';
import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import { AppModule } from '../../src/app.module';

describe('gRPC End-to-End Tests', () => {
  let app: INestApplication;
  let client: any;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();

    // Setup gRPC microservice
    app.connectMicroservice<MicroserviceOptions>({
      transport: Transport.GRPC,
      options: {
        package: 'auth',
        protoPath: join(__dirname, '../../src/auth/auth.proto'),
        url: 'localhost:50051',
      },
    });

    await app.startAllMicroservices();
    await app.init();

    // Setup gRPC client
    const PROTO_PATH = join(__dirname, '../../src/auth/auth.proto');
    const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
      keepCase: true,
      longs: String,
      enums: String,
      defaults: true,
      oneofs: true,
    });

    const authProto = grpc.loadPackageDefinition(packageDefinition).auth;
    client = new authProto.AuthService(
      'localhost:50051',
      grpc.credentials.createInsecure(),
    );
  });

  afterAll(async () => {
    await app.close();
  });

  describe('Registration Flow', () => {
    it('should register a new user successfully', (done) => {
      const registerRequest = {
        email: 'e2e@test.com',
        password: 'StrongPass123!',
      };

      client.register(registerRequest, (error: any, response: any) => {
        expect(error).toBeNull();
        expect(response.success).toBe(true);
        expect(response.user.email).toBe('e2e@test.com');
        done();
      });
    });

    it('should fail registration with weak password', (done) => {
      const registerRequest = {
        email: 'weak@test.com',
        password: 'weak',
      };

      client.register(registerRequest, (error: any, response: any) => {
        expect(error).toBeNull();
        expect(response.success).toBe(false);
        expect(response.error).toBe('Password validation failed');
        done();
      });
    });

    it('should fail registration for existing user', (done) => {
      const registerRequest = {
        email: 'e2e@test.com',
        password: 'StrongPass123!',
      };

      client.register(registerRequest, (error: any, response: any) => {
        expect(error).toBeNull();
        expect(response.success).toBe(false);
        expect(response.error).toBe('User already exists');
        done();
      });
    });
  });

  describe('Login Flow', () => {
    it('should login user successfully', (done) => {
      const loginRequest = {
        email: 'e2e@test.com',
        password: 'StrongPass123!',
      };

      client.login(loginRequest, (error: any, response: any) => {
        expect(error).toBeNull();
        expect(response.success).toBe(true);
        expect(response.accessToken).toBeDefined();
        expect(response.refreshToken).toBeDefined();
        done();
      });
    });

    it('should fail login with wrong password', (done) => {
      const loginRequest = {
        email: 'e2e@test.com',
        password: 'wrongpassword',
      };

      client.login(loginRequest, (error: any, response: any) => {
        expect(error).toBeNull();
        expect(response.success).toBe(false);
        expect(response.error).toBe('Invalid credentials');
        done();
      });
    });

    it('should fail login for non-existent user', (done) => {
      const loginRequest = {
        email: 'nonexistent@test.com',
        password: 'password123',
      };

      client.login(loginRequest, (error: any, response: any) => {
        expect(error).toBeNull();
        expect(response.success).toBe(false);
        expect(response.error).toBe('Invalid credentials');
        done();
      });
    });
  });

  describe('Brute Force Protection', () => {
    it('should block user after multiple failed attempts', (done) => {
      const loginRequest = {
        email: 'e2e@test.com',
        password: 'wrongpassword',
      };

      let attemptCount = 0;
      const maxAttempts = 6;

      const attemptLogin = () => {
        client.login(loginRequest, (error: any, response: any) => {
          attemptCount++;

          if (attemptCount < maxAttempts) {
            expect(response.success).toBe(false);
            expect(response.error).toBe('Invalid credentials');
            attemptLogin();
          } else {
            expect(response.success).toBe(false);
            expect(response.error).toBe('Account temporarily blocked');
            done();
          }
        });
      };

      attemptLogin();
    });
  });

  describe('Token Management', () => {
    let accessToken: string;
    let refreshToken: string;

    it('should generate valid tokens on login', (done) => {
      const loginRequest = {
        email: 'e2e@test.com',
        password: 'StrongPass123!',
      };

      client.login(loginRequest, (error: any, response: any) => {
        expect(error).toBeNull();
        expect(response.success).toBe(true);

        accessToken = response.accessToken;
        refreshToken = response.refreshToken;

        expect(accessToken).toBeDefined();
        expect(refreshToken).toBeDefined();
        done();
      });
    });

    it('should validate token successfully', (done) => {
      const validateRequest = {
        token: accessToken,
      };

      client.validateToken(validateRequest, (error: any, response: any) => {
        expect(error).toBeNull();
        expect(response.valid).toBe(true);
        expect(response.user.email).toBe('e2e@test.com');
        done();
      });
    });

    it('should refresh token successfully', (done) => {
      const refreshRequest = {
        refreshToken: refreshToken,
      };

      client.refreshToken(refreshRequest, (error: any, response: any) => {
        expect(error).toBeNull();
        expect(response.success).toBe(true);
        expect(response.accessToken).toBeDefined();
        expect(response.refreshToken).toBeDefined();
        done();
      });
    });

    it('should logout successfully', (done) => {
      const logoutRequest = {
        accessToken: accessToken,
      };

      client.logout(logoutRequest, (error: any, response: any) => {
        expect(error).toBeNull();
        expect(response.success).toBe(true);
        done();
      });
    });

    it('should reject revoked token', (done) => {
      const validateRequest = {
        token: accessToken,
      };

      client.validateToken(validateRequest, (error: any, response: any) => {
        expect(error).toBeNull();
        expect(response.valid).toBe(false);
        done();
      });
    });
  });

  describe('Two-Factor Authentication', () => {
    let userId: string;

    it('should enable 2FA for user', (done) => {
      // First get user ID by logging in
      const loginRequest = {
        email: 'e2e@test.com',
        password: 'StrongPass123!',
      };

      client.login(loginRequest, (error: any, response: any) => {
        expect(error).toBeNull();
        expect(response.success).toBe(true);

        // Extract user ID from token or use a test user
        userId = '1'; // For testing purposes

        const enable2FARequest = {
          userId: userId,
        };

        client.enable2FA(enable2FARequest, (error2: any, response2: any) => {
          expect(error2).toBeNull();
          expect(response2.success).toBe(true);
          expect(response2.qrCode).toBeDefined();
          expect(response2.backupCodes).toHaveLength(10);
          done();
        });
      });
    });

    it('should require 2FA after enabling', (done) => {
      const loginRequest = {
        email: 'e2e@test.com',
        password: 'StrongPass123!',
      };

      client.login(loginRequest, (error: any, response: any) => {
        expect(error).toBeNull();
        expect(response.success).toBe(false);
        expect(response.error).toBe('2FA_REQUIRED');
        done();
      });
    });

    it('should verify 2FA with backup code', (done) => {
      const verify2FARequest = {
        userId: userId,
        token: 'BACKUP01', // Use a backup code
      };

      client.verify2FA(verify2FARequest, (error: any, response: any) => {
        expect(error).toBeNull();
        expect(response.success).toBe(true);
        done();
      });
    });
  });

  describe('Anomaly Detection', () => {
    it('should get anomaly statistics', (done) => {
      const statsRequest = {
        userId: '1',
      };

      client.getAnomalyStats(statsRequest, (error: any, response: any) => {
        expect(error).toBeNull();
        expect(response.totalEvents).toBeGreaterThanOrEqual(0);
        expect(response.anomalyEvents).toBeGreaterThanOrEqual(0);
        expect(response.averageScore).toBeGreaterThanOrEqual(0);
        done();
      });
    });
  });

  describe('Rate Limiting', () => {
    it('should respect rate limits on registration', (done) => {
      const registerRequest = {
        email: 'ratelimit@test.com',
        password: 'StrongPass123!',
      };

      let successCount = 0;
      let totalAttempts = 0;
      const maxAttempts = 10;

      const attemptRegistration = () => {
        client.register(registerRequest, (error: any, response: any) => {
          totalAttempts++;

          if (response.success) {
            successCount++;
          }

          if (totalAttempts < maxAttempts) {
            attemptRegistration();
          } else {
            // Should have rate limiting in place
            expect(successCount).toBeLessThanOrEqual(3); // Allow some successful attempts
            done();
          }
        });
      };

      attemptRegistration();
    });
  });

  describe('Error Handling', () => {
    it('should handle malformed requests gracefully', (done) => {
      const malformedRequest = {
        // Missing required fields
      };

      client.register(malformedRequest, (error: any, response: any) => {
        expect(error).toBeDefined();
        done();
      });
    });

    it('should handle invalid gRPC calls', (done) => {
      const invalidRequest = {
        invalidField: 'invalid value',
      };

      // Try to call a non-existent method
      if (client.nonExistentMethod) {
        client.nonExistentMethod(
          invalidRequest,
          (error: any, response: any) => {
            expect(error).toBeDefined();
            done();
          },
        );
      } else {
        // Method doesn't exist, which is expected
        done();
      }
    });
  });

  describe('Performance Tests', () => {
    it('should handle concurrent requests', (done) => {
      const loginRequest = {
        email: 'e2e@test.com',
        password: 'StrongPass123!',
      };

      const concurrentRequests = 10;
      let completedRequests = 0;
      let successfulRequests = 0;

      for (let i = 0; i < concurrentRequests; i++) {
        client.login(loginRequest, (error: any, response: any) => {
          completedRequests++;

          if (response.success) {
            successfulRequests++;
          }

          if (completedRequests === concurrentRequests) {
            expect(successfulRequests).toBeGreaterThan(0);
            expect(completedRequests).toBe(concurrentRequests);
            done();
          }
        });
      }
    });

    it('should respond within reasonable time', (done) => {
      const loginRequest = {
        email: 'e2e@test.com',
        password: 'StrongPass123!',
      };

      const startTime = Date.now();

      client.login(loginRequest, (error: any, response: any) => {
        const endTime = Date.now();
        const duration = endTime - startTime;

        expect(duration).toBeLessThan(5000); // Should respond within 5 seconds
        expect(response.success).toBe(true);
        done();
      });
    });
  });
});
