import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  // eslint-disable-next-line @typescript-eslint/explicit-function-return-type
  async onModuleInit() {
    await this.$connect();
  }

  // eslint-disable-next-line @typescript-eslint/explicit-function-return-type
  async onModuleDestroy() {
    return this.$disconnect();
  }
}
