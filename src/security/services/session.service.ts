import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../prisma.service';

export interface CreateSessionInput {
  userId: string;
  accessTokenJti: string;
  refreshTokenJti: string;
  ipAddress: string;
  userAgent?: string | null;
  expiresAt: Date;
}

@Injectable()
export class SessionService {
  constructor(private readonly prismaService: PrismaService) {}

  async create(input: CreateSessionInput) {
    return this.prismaService.session.create({
      data: {
        userId: input.userId,
        accessTokenJti: input.accessTokenJti,
        refreshTokenJti: input.refreshTokenJti,
        ipAddress: input.ipAddress,
        userAgent: input.userAgent ?? null,
        expiresAt: input.expiresAt,
        isActive: true,
      },
    });
  }

  findByRefreshJti(refreshTokenJti: string) {
    return this.prismaService.session.findUnique({
      where: { refreshTokenJti },
    });
  }

  async deactivate(id: string) {
    return this.prismaService.session.update({
      where: { id },
      data: { isActive: false },
    });
  }

  async deactivateAll(userId: string) {
    const { count } = await this.prismaService.session.updateMany({
      where: { userId, isActive: true },
      data: { isActive: false },
    });
    return count;
  }
}
