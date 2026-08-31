-- CreateEnum
CREATE TYPE "public"."ReservationState" AS ENUM ('active', 'expired', 'released_by_admin');

-- CreateTable
CREATE TABLE "public"."username_reservations" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "username" TEXT NOT NULL,
    "state" "public"."ReservationState" NOT NULL DEFAULT 'active',
    "reservedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "releasedAt" TIMESTAMP(3),

    CONSTRAINT "username_reservations_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "username_reservations_username_key" ON "public"."username_reservations"("username");

-- CreateIndex
CREATE INDEX "username_reservations_userId_idx" ON "public"."username_reservations"("userId");

-- CreateIndex
CREATE INDEX "username_reservations_state_expiresAt_idx" ON "public"."username_reservations"("state", "expiresAt");

-- AddForeignKey
ALTER TABLE "public"."username_reservations" ADD CONSTRAINT "username_reservations_userId_fkey" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
