-- История изменений Linked Telegram Username (users.telegramUsername).
-- Бессрочное per-user хранение; отображается в Settings, задел под поиск по истории.

CREATE TABLE "public"."telegram_username_history" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "telegramUsername" TEXT,
    "previousUsername" TEXT,
    "eventType" TEXT NOT NULL,
    "source" TEXT,
    "changedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "telegram_username_history_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "telegram_username_history_userId_changedAt_idx"
    ON "public"."telegram_username_history"("userId", "changedAt");

CREATE INDEX "telegram_username_history_telegramUsername_idx"
    ON "public"."telegram_username_history"("telegramUsername");

ALTER TABLE "public"."telegram_username_history"
    ADD CONSTRAINT "telegram_username_history_userId_fkey"
    FOREIGN KEY ("userId") REFERENCES "public"."users"("id")
    ON DELETE CASCADE ON UPDATE CASCADE;

-- Backfill 1: текущее значение telegramUsername каждого пользователя.
INSERT INTO "public"."telegram_username_history"
    ("id", "userId", "telegramUsername", "previousUsername", "eventType", "source", "changedAt")
SELECT gen_random_uuid()::text, u."id", u."telegramUsername", NULL,
       'migrated', 'audit_migration', COALESCE(u."updatedAt", NOW())
FROM "public"."users" u
WHERE u."telegramUsername" IS NOT NULL
  AND NOT EXISTS (
      SELECT 1 FROM "public"."telegram_username_history" h
      WHERE h."userId" = u."id" AND h."telegramUsername" = u."telegramUsername"
  );

-- Backfill 2: исторические значения из telegram_identity_audit (previousData->>'telegramUsername').
-- Дедуп по (userId, значение) с выбором самой ранней записи.
INSERT INTO "public"."telegram_username_history"
    ("id", "userId", "telegramUsername", "previousUsername", "eventType", "source", "changedAt")
SELECT DISTINCT ON (a."userId", a."prev")
       gen_random_uuid()::text, a."userId", a."prev", NULL,
       'migrated', 'audit_migration', a."createdAt"
FROM (
    SELECT "userId",
           "createdAt",
           "previousData" ->> 'telegramUsername' AS "prev"
    FROM "public"."telegram_identity_audit"
    WHERE "previousData" ->> 'telegramUsername' IS NOT NULL
      AND "eventType" IN (
          'telegram_username_updated',
          'telegram_username_removed',
          'telegram_account_revoked'
      )
) a
WHERE a."prev" IS NOT NULL
  AND NOT EXISTS (
      SELECT 1 FROM "public"."telegram_username_history" h
      WHERE h."userId" = a."userId" AND h."telegramUsername" = a."prev"
  )
ORDER BY a."userId", a."prev", a."createdAt" ASC;
