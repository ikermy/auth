-- CreateEnum
CREATE TYPE "public"."UserRole" AS ENUM ('user', 'admin');

-- AlterTable
ALTER TABLE "public"."users" ADD COLUMN "role" "public"."UserRole" NOT NULL DEFAULT 'user';
