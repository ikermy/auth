FROM node:22-alpine AS builder

WORKDIR /app

# Устанавливаем зависимости для сборки
RUN apk add --no-cache \
    netcat-openbsd \
    protobuf-dev \
    python3 \
    make \
    g++

# Копируем package files
COPY package*.json ./

# Устанавливаем все зависимости (включая dev для сборки)
RUN npm ci

# Копируем исходный код
COPY . .

# Генерируем Prisma Client
RUN npx prisma generate

# Генерируем proto файлы
RUN npm run proto:gen

# Собираем приложение
RUN npm run build

# Production stage
FROM node:22-alpine AS production

WORKDIR /app

# Устанавливаем только production зависимости
RUN apk add --no-cache \
    netcat-openbsd \
    protobuf-dev

# Создаем пользователя для безопасности
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nestjs -u 1001

# Копируем package files
COPY package*.json ./

# Устанавливаем только production зависимости
RUN npm ci --only=production && npm cache clean --force

# Копируем собранное приложение
COPY --from=builder --chown=nestjs:nodejs /app/dist ./dist
COPY --from=builder --chown=nestjs:nodejs /app/prisma ./prisma
COPY --from=builder --chown=nestjs:nodejs /app/generated ./generated

# Меняем владельца файлов
RUN chown -R nestjs:nodejs /app

# Переключаемся на непривилегированного пользователя
USER nestjs

# Открываем порт
EXPOSE 50051

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD nc -z localhost 50051 || exit 1

# Запускаем приложение
CMD ["npm", "run", "start:prod"]
