import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Metadata } from '@grpc/grpc-js';
import { EnhancedJwtService } from '../../security/services/enhanced-jwt.service';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import { AuthPrincipal, PRINCIPAL_KEY } from './principal';

@Injectable()
export class GrpcAuthGuard implements CanActivate {
  constructor(
    private readonly jwtService: EnhancedJwtService,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) {
      return true;
    }

    const rpc = context.switchToRpc();
    const metadata = rpc.getContext<Metadata>();

    const authHeader = metadata.get('authorization')[0] as string | undefined;
    if (!authHeader) {
      throw new UnauthorizedException('Missing authorization token');
    }

    const token = authHeader.startsWith('Bearer ')
      ? authHeader.slice(7)
      : authHeader;

    let payload;
    try {
      payload = await this.jwtService.verifyToken(token);
    } catch {
      throw new UnauthorizedException('Invalid or expired token');
    }

    if (!payload || !payload.sub) {
      throw new UnauthorizedException('Invalid token payload');
    }

    const principal: AuthPrincipal = {
      userId: payload.sub,
      email: payload.email,
      jti: payload.jti,
      type: payload.type,
    };

    (rpc.getContext() as Record<symbol, unknown>)[PRINCIPAL_KEY] = principal;
    return true;
  }
}
