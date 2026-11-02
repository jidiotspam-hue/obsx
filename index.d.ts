/**
 * OBSX Security — Official TypeScript Type Definitions
 * Open-source client integrity attestation, micro-proof-of-work, and anti-automation.
 */

export interface OBSXSession {
  token: string;
  session: string;
  challenge: string;
  difficulty: number;
  nonce?: string;
  rk?: string;
  expiresAt?: number;
  endpoint?: string;
}

export interface OBSXSeal {
  token: string;
  nonce?: string;
  ts: number;
  sig: string;
}

export interface OBSXAttestation {
  token: string;
  nonce?: string;
  verdict?: 'accept' | 'review' | 'reject';
  risk?: number;
  reasons?: string[];
}

export interface OBSXVerifyOptions {
  secret: string;
  clientIp?: string;
  proxyHeaders?: string[];
  maxDurationMs?: number;
}

export interface OBSXReason {
  code: string;
  text?: string;
  detail?: string;
  weight?: number;
}

export interface OBSXVerdict {
  ok: boolean;
  verdict: 'accept' | 'review' | 'reject';
  risk: number;
  sealed?: 'ok' | 'invalid' | 'stale' | 'missing' | 'none';
  reasons: OBSXReason[];
  action?: string;
  timestamp?: number;
}

export interface OBSXClientOptions {
  site: string;
  endpoint?: string;
  callback?: (token: string) => void;
  fresh?: boolean;
  consume?: boolean;
}

export interface OBSXClient {
  version: string;
  init(options?: OBSXClientOptions): Promise<OBSXSession>;
  getAttestation(options?: { fresh?: boolean; consume?: boolean }): Promise<OBSXAttestation>;
  sign(payload?: Record<string, unknown>): Promise<OBSXSeal>;
  seal<T extends Record<string, unknown>>(payload?: T): Promise<T & { obsx: OBSXSeal }>;
  verify(payload?: Record<string, unknown>): Promise<OBSXVerdict>;
  reset(): void;
  render(element: HTMLElement | string, options?: { site?: string; theme?: 'dark' | 'light'; callback?: (token: string) => void }): void;
}

declare global {
  interface Window {
    OBSX?: OBSXClient;
    Veritas?: OBSXClient;
    Tracer?: OBSXClient;
  }
}

/**
 * Server-Side Token Verification
 * Deterministically verifies HMAC signature, solves micro-PoW puzzle, burns single-use nonce,
 * and audits runtime proxy/CDP tampering indicators.
 */
export function verifyToken(
  token: string,
  options: OBSXVerifyOptions
): Promise<OBSXVerdict>;

export default OBSXClient;
