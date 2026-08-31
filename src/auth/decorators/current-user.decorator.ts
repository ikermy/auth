import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { PRINCIPAL_KEY } from '../guards/principal';

export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext) => {
    const rpc = ctx.switchToRpc();
    return (rpc.getContext() as Record<symbol, unknown>)[PRINCIPAL_KEY];
  },
);
