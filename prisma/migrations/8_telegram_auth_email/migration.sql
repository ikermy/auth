-- AlterTable: email становится nullable (telegram-аккаунты могут не иметь email).
-- Postgres допускает несколько NULL в уникальном индексе, поэтому уникальность email сохраняется.
ALTER TABLE "public"."users" ALTER COLUMN "email" DROP NOT NULL;

-- AddColumn: служебный Telegram-логин (placeholder tg_...@secure.local)
ALTER TABLE "public"."users" ADD COLUMN "telegramAuth" TEXT;

-- Data migration: переносим сгенерированные системой служебные tg_ email в новое поле
-- и освобождаем email для реального адреса пользователя.
UPDATE "public"."users"
SET "telegramAuth" = "email",
    "email" = NULL
WHERE "email" LIKE 'tg\_%@secure.local';
