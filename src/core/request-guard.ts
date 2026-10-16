// Cross-site and DNS-rebinding protection for the canvas server.
//
// The canvas API is unauthenticated, so the browser must not let arbitrary
// websites talk to it. Non-browser clients (CLI, MCP server, curl) send no
// Origin header and are always allowed; browsers always send Origin on
// cross-origin fetch/XHR/WebSocket requests, so those are checked here.

const LOOPBACK_HOSTNAMES = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);
const LOOPBACK_BIND_HOSTS = new Set(['localhost', '127.0.0.1', '::1']);

export interface RequestGuardOptions {
  // The HOST the server binds. A loopback bind also enforces a loopback Host
  // header, which defeats DNS rebinding.
  bindHost: string;
  // Extra origins allowed to call the API cross-origin (EXCALIDRAW_ALLOWED_ORIGINS).
  allowedOrigins?: readonly string[];
}

export interface RequestGuard {
  isAllowedHost(hostHeader: string | undefined): boolean;
  isAllowedOrigin(originHeader: string | undefined, hostHeader: string | undefined): boolean;
  isAllowedRequest(headers: { origin?: string; host?: string }): boolean;
}

export function parseAllowedOrigins(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(',')
    .map(entry => entry.trim())
    .filter(entry => entry.length > 0)
    .map(entry => {
      try {
        return new URL(entry).origin;
      } catch {
        return entry;
      }
    });
}

function hostnameOf(hostHeader: string): string | null {
  try {
    return new URL(`http://${hostHeader}`).hostname.toLowerCase();
  } catch {
    return null;
  }
}

export function createRequestGuard(options: RequestGuardOptions): RequestGuard {
  const enforceLoopbackHost = LOOPBACK_BIND_HOSTS.has(options.bindHost);
  const allowedOrigins = new Set(options.allowedOrigins ?? []);

  function isAllowedHost(hostHeader: string | undefined): boolean {
    if (!enforceLoopbackHost || !hostHeader) return true;
    const hostname = hostnameOf(hostHeader);
    return hostname !== null && LOOPBACK_HOSTNAMES.has(hostname);
  }

  function isAllowedOrigin(originHeader: string | undefined, hostHeader: string | undefined): boolean {
    if (originHeader === undefined) return true;
    if (allowedOrigins.has(originHeader)) return true;
    // `null` origins (sandboxed iframes, file://) are never same-origin.
    if (originHeader === 'null' || !hostHeader) return false;
    try {
      return new URL(originHeader).host.toLowerCase() === hostHeader.toLowerCase();
    } catch {
      return false;
    }
  }

  return {
    isAllowedHost,
    isAllowedOrigin,
    isAllowedRequest(headers) {
      return isAllowedHost(headers.host) && isAllowedOrigin(headers.origin, headers.host);
    },
  };
}
