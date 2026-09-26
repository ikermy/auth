-- Migration 9a: case-insensitive identity + password provenance flag.
--
-- 1. passwordSetByUser  — отличает пользовательский пароль от системного
--    placeholder у Telegram-only аккаунтов (set vs change password).
-- 2. emailVerifiedAt    — время фактического подтверждения email.
-- 3. lower(email)       — регистронезависимая уникальность email.
-- 4. lower(username)    — регистронезависимая уникальность username.
--
-- ВАЖНО: перед нормализацией выполняется pre-flight проверка. Если в БД уже есть
-- конфликтующие имена (username/email, различающиеся только регистром), миграция
-- аварийно завершается с сообщением, а не портит данные. Конфликты нужно
-- разрешить вручную и повторить миграцию.

DO $$
DECLARE
  dup_username TEXT;
  dup_email TEXT;
BEGIN
  SELECT lower("username") INTO dup_username
  FROM "public"."users"
  WHERE "username" IS NOT NULL
  GROUP BY lower("username")
  HAVING count(*) > 1
  LIMIT 1;

  IF dup_username IS NOT NULL THEN
    RAISE EXCEPTION
      'Migration 9a aborted: case-insensitive username conflict for "%". Resolve duplicates before applying.',
      dup_username;
  END IF;

  SELECT lower("email") INTO dup_email
  FROM "public"."users"
  WHERE "email" IS NOT NULL
  GROUP BY lower("email")
  HAVING count(*) > 1
  LIMIT 1;

  IF dup_email IS NOT NULL THEN
    RAISE EXCEPTION
      'Migration 9a aborted: case-insensitive email conflict for "%". Resolve duplicates before applying.',
      dup_email;
  END IF;
END $$;

-- 1. Новые колонки.
ALTER TABLE "public"."users"
    ADD COLUMN "emailVerifiedAt" TIMESTAMP(3),
    ADD COLUMN "passwordSetByUser" BOOLEAN NOT NULL DEFAULT false;

-- 2. Backfill: у email-регистраций пароль всегда задан пользователем.
UPDATE "public"."users"
SET "passwordSetByUser" = true
WHERE "origin" = 'email';

-- 3. Backfill времени подтверждения email для уже подтверждённых.
UPDATE "public"."users"
SET "emailVerifiedAt" = COALESCE("updatedAt", NOW())
WHERE "isEmailVerified" = true
  AND "email" IS NOT NULL
  AND "emailVerifiedAt" IS NULL;

-- 4. Нормализация регистра (конфликты исключены проверкой выше).
UPDATE "public"."users" SET "email" = lower("email") WHERE "email" IS NOT NULL;
UPDATE "public"."users" SET "username" = lower("username") WHERE "username" IS NOT NULL;

-- 5. Функциональные уникальные индексы. Плоские users_email_key/users_username_key
--    оставлены, т.к. их требует Prisma @unique. lower()-индексы дают гарантию СУБД.
CREATE UNIQUE INDEX "users_email_lower_key" ON "public"."users" (lower("email"));
CREATE UNIQUE INDEX "users_username_lower_key" ON "public"."users" (lower("username"));
