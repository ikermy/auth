-- AlterTable: SecurityEvent.userId становится nullable (системные события без User, AUDIT-01)
ALTER TABLE "public"."security_events" ALTER COLUMN "userId" DROP NOT NULL;
