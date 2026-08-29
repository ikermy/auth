FROM node:22

WORKDIR /app

# Устанавливаем зависимости для разработки
RUN apt-get update && apt-get install -y \
    netcat-openbsd \
    protobuf-compiler \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Копируем package files
COPY package*.json ./

# Устанавливаем зависимости (включая dev)
RUN npm ci

# Копируем исходный код
COPY . .

# Генерируем Prisma Client
RUN npx prisma generate

# Генерируем proto файлы
RUN npm run proto:gen

# Открываем порты для приложения и дебага
EXPOSE 50051 9229

# Запускаем в режиме разработки с дебагом
CMD ["npm", "run", "start:debug"]
