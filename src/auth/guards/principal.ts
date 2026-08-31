export interface AuthPrincipal {
  userId: string;
  email?: string;
  jti?: string;
  type?: string;
}

export const PRINCIPAL_KEY = Symbol('authPrincipal');
