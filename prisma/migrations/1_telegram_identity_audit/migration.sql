-- CreateTable
CREATE TABLE "public"."telegram_identity_audit" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "eventType" TEXT NOT NULL,
    "previousData" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "telegram_identity_audit_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "telegram_identity_audit_userId_idx" ON "public"."telegram_identity_audit"("userId");

-- AddForeignKey
ALTER TABLE "public"."telegram_identity_audit" ADD CONSTRAINT "telegram_identity_audit_userId_fkey" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
