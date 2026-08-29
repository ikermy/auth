import { Module } from '@nestjs/common';
import { ScheduleModule } from '@nestjs/schedule';
import { UserMonitoringService } from './user-monitoring.service';
import { PrismaService } from '../prisma.service';

@Module({
  imports: [ScheduleModule.forRoot()],
  providers: [UserMonitoringService, PrismaService],
  exports: [UserMonitoringService],
})
export class CronModule {}
