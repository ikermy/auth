-- Migration 9b: срок жизни токена верификации email.
--
-- emailVerificationToken уже существует, но без TTL. Для безопасной проверки
-- «токен истёк» добавляем emailVerificationExpiresAt.

ALTER TABLE "public"."users"
    ADD COLUMN "emailVerificationExpiresAt" TIMESTAMP(3);
