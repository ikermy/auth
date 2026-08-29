FROM node:22-alpine

WORKDIR /app

# Устанавливаем зависимости для stage
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

# Удаляем dev зависимости
RUN npm prune --production

# Создаем пользователя для безопасности
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nestjs -u 1001

# Меняем владельца файлов
RUN chown -R nestjs:nodejs /app
USER nestjs

# Открываем порт
EXPOSE 50051

# Запускаем приложение
CMD ["npm", "run", "start:prod"]
