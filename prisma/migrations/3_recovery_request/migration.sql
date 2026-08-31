-- CreateEnum
CREATE TYPE "public"."RecoveryStatus" AS ENUM ('pending_review', 'approved', 'rejected', 'cancelled', 'needs_review', 'granted');

-- CreateTable
CREATE TABLE "public"."recovery_requests" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "status" "public"."RecoveryStatus" NOT NULL DEFAULT 'pending_review',
    "reason" TEXT,
    "decidedBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "decidedAt" TIMESTAMP(3),
    "grantExpiresAt" TIMESTAMP(3),

    CONSTRAINT "recovery_requests_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "recovery_requests_userId_idx" ON "public"."recovery_requests"("userId");

-- CreateIndex
CREATE INDEX "recovery_requests_status_idx" ON "public"."recovery_requests"("status");

-- AddForeignKey
ALTER TABLE "public"."recovery_requests" ADD CONSTRAINT "recovery_requests_userId_fkey" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
