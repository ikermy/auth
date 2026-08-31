-- CreateEnum
CREATE TYPE "public"."AccountOrigin" AS ENUM ('email', 'telegram');

-- AlterTable
ALTER TABLE "public"."users" ADD COLUMN "origin" "public"."AccountOrigin" NOT NULL DEFAULT 'email';
