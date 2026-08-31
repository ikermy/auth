import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Kafka, Producer } from 'kafkajs';

/**
 * Публикация security-событий в Kafka (§9.12). Auth не обязан полагаться на
 * Kafka для корректной работы: при недоступности брокера события продолжают
 * писаться в БД, а Kafka-публикация безопасно пропускается (fail-open).
 * Топик по умолчанию — security_events (потребляет Notifications Service).
 */
@Injectable()
export class KafkaProducerService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(KafkaProducerService.name);
  private producer: Producer | undefined;
  private ready = false;
  private readonly topic: string;

  constructor(private readonly configService: ConfigService) {
    this.topic = this.configService.get<string>(
      'KAFKA_SECURITY_TOPIC',
      'security_events',
    );
  }

  async onModuleInit() {
    try {
      const brokers = (
        this.configService.get<string>('KAFKA_BROKERS', 'kafka:9092') ||
        'kafka:9092'
      )
        .split(',')
        .map((b) => b.trim())
        .filter(Boolean);

      if (brokers.length === 0) {
        this.logger.warn('KAFKA_BROKERS empty, Kafka publishing disabled');
        return;
      }

      const kafka = new Kafka({ clientId: 'auth-service', brokers });
      this.producer = kafka.producer();
      await this.producer.connect();
      this.ready = true;
      this.logger.log(`✅ Connected to Kafka at ${brokers.join(',')}`);
    } catch (error) {
      this.logger.warn(
        `Kafka unavailable, security events will only be persisted to DB: ${(error as Error).message}`,
      );
      this.ready = false;
    }
  }

  async onModuleDestroy() {
    if (this.producer && this.ready) {
      await this.producer.disconnect().catch(() => undefined);
    }
  }

  async publish(event: Record<string, unknown>): Promise<void> {
    if (!this.ready || !this.producer) {
      return;
    }
    try {
      await this.producer.send({
        topic: this.topic,
        messages: [{ value: JSON.stringify(event) }],
      });
    } catch (error) {
      this.logger.error(
        `Failed to publish security event to Kafka: ${(error as Error).message}`,
      );
    }
  }
}
