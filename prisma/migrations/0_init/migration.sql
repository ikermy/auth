-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateEnum
CREATE TYPE "public"."EventType" AS ENUM ('ANOMALY_DETECTED', 'TWO_FA_ENABLED', 'PASSWORD_CHANGED', 'SUSPICIOUS_ACTIVITY', 'SUCCESS', 'ERROR', 'RATE_LIMIT_EXCEEDED', 'AUTH_ATTEMPT', 'REGISTRATION', 'TOKEN_REFRESH');

-- CreateEnum
CREATE TYPE "public"."Severity" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateTable
CREATE TABLE "public"."users" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "password" TEXT NOT NULL,
    "passwordChangedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "failedLoginAttempts" INTEGER NOT NULL DEFAULT 0,
    "lastLoginAt" TIMESTAMP(3),
    "lastLoginIp" TEXT,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "isEmailVerified" BOOLEAN NOT NULL DEFAULT false,
    "emailVerificationToken" TEXT,
    "passwordResetToken" TEXT,
    "passwordResetExpiresAt" TIMESTAMP(3),
    "username" TEXT,
    "nickname" TEXT,
    "telegramId" TEXT,
    "telegramUsername" TEXT,
    "telegramFirstName" TEXT,
    "telegramLastName" TEXT,
    "telegramPhotoUrl" TEXT,
    "isTelegramVerified" BOOLEAN NOT NULL DEFAULT false,
    "twoFactorEnabled" BOOLEAN NOT NULL DEFAULT false,
    "twoFactorSecret" TEXT,
    "twoFactorPendingSecret" TEXT,
    "twoFactorPendingSecretCreatedAt" TIMESTAMP(3),
    "backupCodes" TEXT[],
    "seedPhraseEnabled" BOOLEAN NOT NULL DEFAULT false,
    "seedPhraseHash" TEXT,
    "seedPhraseSalt" TEXT,
    "seedPhraseAttempts" INTEGER NOT NULL DEFAULT 0,
    "seedPhraseLockedUntil" TIMESTAMP(3),
    "seedPhraseLastVerifiedAt" TIMESTAMP(3),
    "seedPhraseVerificationCount" INTEGER NOT NULL DEFAULT 0,
    "anomalyScore" DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    "lastAnomalyAt" TIMESTAMP(3),
    "trustedDevices" TEXT[],
    "encryptedData" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."login_attempts" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "email" TEXT NOT NULL,
    "ipAddress" TEXT NOT NULL,
    "userAgent" TEXT,
    "success" BOOLEAN NOT NULL,
    "failureReason" TEXT,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "login_attempts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."sessions" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "accessTokenJti" TEXT NOT NULL,
    "refreshTokenJti" TEXT NOT NULL,
    "ipAddress" TEXT NOT NULL,
    "userAgent" TEXT,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastAccessedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."security_events" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "eventType" "public"."EventType" NOT NULL,
    "severity" "public"."Severity" NOT NULL,
    "description" TEXT NOT NULL,
    "metadata" JSONB,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "security_events_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "public"."users"("email");

-- CreateIndex
CREATE UNIQUE INDEX "users_username_key" ON "public"."users"("username");

-- CreateIndex
CREATE UNIQUE INDEX "users_telegramId_key" ON "public"."users"("telegramId");

-- CreateIndex
CREATE INDEX "login_attempts_email_timestamp_idx" ON "public"."login_attempts"("email", "timestamp");

-- CreateIndex
CREATE INDEX "login_attempts_ipAddress_timestamp_idx" ON "public"."login_attempts"("ipAddress", "timestamp");

-- CreateIndex
CREATE UNIQUE INDEX "sessions_accessTokenJti_key" ON "public"."sessions"("accessTokenJti");

-- CreateIndex
CREATE UNIQUE INDEX "sessions_refreshTokenJti_key" ON "public"."sessions"("refreshTokenJti");

-- CreateIndex
CREATE INDEX "sessions_userId_isActive_idx" ON "public"."sessions"("userId", "isActive");

-- CreateIndex
CREATE INDEX "sessions_accessTokenJti_idx" ON "public"."sessions"("accessTokenJti");

-- CreateIndex
CREATE INDEX "sessions_refreshTokenJti_idx" ON "public"."sessions"("refreshTokenJti");

-- CreateIndex
CREATE INDEX "security_events_userId_timestamp_idx" ON "public"."security_events"("userId", "timestamp");

-- CreateIndex
CREATE INDEX "security_events_eventType_severity_idx" ON "public"."security_events"("eventType", "severity");

-- AddForeignKey
ALTER TABLE "public"."login_attempts" ADD CONSTRAINT "login_attempts_userId_fkey" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."sessions" ADD CONSTRAINT "sessions_userId_fkey" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "public"."security_events" ADD CONSTRAINT "security_events_userId_fkey" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
