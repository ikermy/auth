import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { join } from 'path';
import { readFileSync } from 'fs';
import { ServerCredentials } from '@grpc/grpc-js';
import { Logger } from '@nestjs/common';

const logger = new Logger('AppConfig');

export const grpcConfigFactory = (): MicroserviceOptions => ({
  transport: Transport.GRPC,
  options: {
    url: '0.0.0.0:50051',
    package: 'auth',
    protoPath: join(__dirname, '..', 'auth', 'auth.proto'),
  },
});

export const grpcConfig: MicroserviceOptions = {
  transport: Transport.GRPC,
  options: {
    url: process.env.GRPC_URL || '0.0.0.0:50051',
    package: process.env.GRPC_PACKAGE || 'auth',
    protoPath: join(__dirname, '..', 'auth', 'auth.proto'),
    credentials:
      process.env.TLS_ENABLED === 'true'
        ? (() => {
            try {
              const caPath = process.env.TLS_CA_PATH || './certs/ca.crt';
              const keyPath = process.env.TLS_KEY_PATH || './certs/server.key';
              const certPath =
                process.env.TLS_CERT_PATH || './certs/server.crt';

              // Валидация путей к сертификатам
              if (
                !caPath ||
                caPath.trim().length === 0 ||
                caPath.length > 500
              ) {
                throw new Error('Invalid CA certificate path');
              }

              if (
                !keyPath ||
                keyPath.trim().length === 0 ||
                keyPath.length > 500
              ) {
                throw new Error('Invalid private key path');
              }

              if (
                !certPath ||
                certPath.trim().length === 0 ||
                certPath.length > 500
              ) {
                throw new Error('Invalid certificate path');
              }

              try {
                const caCert = readFileSync(caPath);
                const privateKey = readFileSync(keyPath);
                const certChain = readFileSync(certPath);

                return ServerCredentials.createSsl(
                  caCert,
                  [
                    {
                      private_key: privateKey,
                      cert_chain: certChain,
                    },
                  ],
                  true, // requestClientCertificate (mTLS)
                );
              } catch (fileError) {
                logger.error(
                  `TLS certificate read error: ${(fileError as Error).message}`,
                );
                return undefined;
              }
            } catch (error) {
              logger.error(
                `TLS configuration error: ${(error as Error).message}`,
              );
              return undefined;
            }
          })()
        : undefined,
  },
};

export const kafkaConfig: MicroserviceOptions = {
  transport: Transport.KAFKA,
  options: {
    client: {
      brokers: ['localhost:9092'],
    },
    consumer: {
      groupId: 'auth-consumer',
    },
  },
};
