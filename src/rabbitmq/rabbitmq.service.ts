import { Injectable } from '@nestjs/common';
import { AmqpConnection } from '@golevelup/nestjs-rabbitmq';
import { AppLogger } from '../common/services/logger/logger.service';

@Injectable()
export class RabbitmqService {
  constructor(
    private readonly amqpConnection: AmqpConnection,
    private readonly logger: AppLogger,
  ) {}

  /**
   * Publishes a message to a RabbitMQ exchange.
   * @param {string} exchange - The name of the RabbitMQ exchange.
   * @param {string} routingKey - The routing key for the message.
   * @param {any} message - The message payload.
   * @returns {Promise<void>} - Resolves when the message is published.
   */
  async publish(
    exchange: string,
    routingKey: string,
    message: object,
  ): Promise<void> {
    try {
      this.logger.log(
        `Publishing message to exchange: ${exchange}, routingKey: ${routingKey}`,
      );
      await this.amqpConnection.publish(exchange, routingKey, message);
      this.logger.log(
        `Message published successfully: ${JSON.stringify(message)}`,
      );
    } catch (error) {
      this.logger.error(
        `Failed to publish message: ${error.message}`,
        error.stack,
      );
      throw error;
    }
  }
}
