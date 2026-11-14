export interface OBSXSession {
  token: string;
  session: string;
  endpoint: string;
  siteKey: string;
  mode: 'enforce' | 'passive';
  nonce: string | number;
  rk?: string;
  startTime: number;
  expiresAt?: number;
  blockOpenAiScrapers?: boolean;
}

export interface OBSXSeal {
  obsx: {
    token: string;
    nonce?: string | number;
    mode: 'enforce' | 'passive';
    ts: number;
    sig: string;
  };
  [key: string]: unknown;
}

export interface OBSXAttestation {
  token: string | null;
  nonce: string | number | null;
  mode: 'enforce' | 'passive';
}

export interface OBSXVerifyOptions {
  secretKey?: string;
  secret?: string;
  endpoint?: string;
  local?: boolean;
  project?: Record<string, unknown>;
  projectId?: string;
  clientIp?: string;
  clientUa?: string;
  headers?: Record<string, string | string[] | undefined>;
  proxyHeaders?: string[];
  nonce?: string | number;
  timeoutMs?: number;
}

export interface OBSXRequestLike {
  headers?: Record<string, string | string[] | undefined>;
  body?: unknown;
  ip?: string;
  method?: string;
  url?: string;
  socket?: { remoteAddress?: string };
}

export interface OBSXReason {
  code: string;
  weight?: number;
  detail?: string;
  text?: string;
}

export interface OBSXVerdict {
  ok: boolean;
  verdict: 'accept' | 'review' | 'reject' | 'observe';
  shadowVerdict?: 'accept' | 'review' | 'reject';
  allowed: boolean;
  mode: 'enforce' | 'passive';
  risk: number;
  sealed?: 'ok' | 'invalid' | 'stale' | 'missing' | 'none';
  message?: string;
  reasons: OBSXReason[];
}

export interface OBSXMiddlewareOptions extends OBSXVerifyOptions {
  allowReview?: boolean;
  blockReview?: boolean;
  statusCode?: number;
  onReject?: (verdict: OBSXVerdict, req: unknown, res: unknown, next?: unknown) => unknown;
}

export interface OBSXClient {
  readonly version: string;
  init(options?: { site?: string; mode?: 'enforce' | 'passive'; endpoint?: string; force?: boolean }): Promise<OBSXSession>;
  flush(): Promise<void>;
  reset(): void;
  rehandshake(options?: { site?: string; mode?: 'enforce' | 'passive'; endpoint?: string }): Promise<OBSXAttestation>;
  getAttestation(options?: { site?: string; mode?: 'enforce' | 'passive'; endpoint?: string; fresh?: boolean; consume?: boolean }): Promise<OBSXAttestation>;
  render(
    containerOrSelector: HTMLElement | string,
    options?: { theme?: 'dark' | 'light'; site?: string; endpoint?: string; mode?: 'enforce' | 'passive'; callback?: (token: string | null, attestation?: OBSXAttestation) => void }
  ): void;
  protectForm(
    formOrSelector: HTMLFormElement | string,
    options?: { site?: string; mode?: 'enforce' | 'passive'; endpoint?: string; onAttested?: (attestation: OBSXAttestation) => void }
  ): HTMLFormElement | null;
  sign(payload?: Record<string, unknown>): Promise<OBSXSeal['obsx']>;
  seal<T extends Record<string, unknown>>(payload?: T): Promise<T & OBSXSeal>;
  verify(payload?: Record<string, unknown>): Promise<OBSXVerdict>;
  enableRecaptchaCompat(options?: { site?: string; force?: boolean }): unknown;
}

declare global {
  interface Window {
    OBSX?: OBSXClient;
    Veritas?: OBSXClient;
    Tracer?: OBSXClient;
  }
}

export function verifyToken(
  tokenOrPayload: string | OBSXSeal | OBSXRequestLike | Request | Record<string, unknown>,
  options?: OBSXVerifyOptions
): Promise<OBSXVerdict>;

export const verify: typeof verifyToken;
export const verifyRequest: typeof verifyToken;

export function middleware(
  options?: OBSXMiddlewareOptions
): (req: unknown, res: unknown, next?: (err?: unknown) => void) => Promise<unknown>;

export const protect: typeof middleware;

export function verifyActionSeal(
  rk: string,
  session: string,
  ts: number,
  nonce: string | number,
  payload: Record<string, unknown>,
  sig: string
): boolean;

export const core: Record<string, unknown>;
export const crypto: Record<string, unknown>;
export const telemetry: Record<string, unknown>;
export const kv: Record<string, unknown>;
export function getKv(): unknown;
export const MemoryStore: unknown;
