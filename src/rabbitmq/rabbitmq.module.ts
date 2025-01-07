import { Module } from '@nestjs/common';
import { RabbitMQModule } from '@golevelup/nestjs-rabbitmq';
import { RabbitmqService } from './rabbitmq.service';

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
  providers: [RabbitmqService],
  exports: [RabbitmqService], // Export for use in other modules
})
export class RabbitmqModule {}
