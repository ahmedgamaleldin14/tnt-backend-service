import { Logger, Module } from '@nestjs/common';
import { RabbitMQModule } from '@golevelup/nestjs-rabbitmq';
import { RabbitmqService } from './rabbitmq.service';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AppLogger } from '../common/services/logger/logger.service';

@Module({
  imports: [
    ConfigModule,
    RabbitMQModule.forRootAsync(RabbitMQModule, {
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        exchanges: [
          {
            name: 'ticktalk_exchange',
            type: 'direct',
          },
        ],
        uri: configService.get<string>('RABBITMQ_URI'), // Access environment variable
        connectionInitOptions: { wait: false },
      }),
    }),
  ],
  providers: [RabbitmqService, AppLogger, Logger],
  exports: [RabbitmqService],
})
export class RabbitmqModule {}
