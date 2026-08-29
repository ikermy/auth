### **Для запуска проекта из корневой директории
```bash
docker compose up --build
```

### **Для запуска проекта из корневой директории на production
```bash
docker compose -f docker-compose.prod.yml up --build
```


### **Для создания базы данных
```bash
docker compose exec app npx prisma db push
docker compose exec app npx prisma generate
```

### *Для создания базы данных на production
```bash
docker compose -f docker-compose.prod.yml exec auth_app npx prisma db push
docker compose -f docker-compose.prod.yml exec auth_app npx prisma generate
```


## License
UNLICENSED
