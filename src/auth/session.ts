const encoder = new TextEncoder();

export const SESSION_COOKIE = "webdav_session";
export const SESSION_MAX_AGE_SECONDS = 30 * 24 * 60 * 60;
export const SESSION_SHORT_TTL_MS = 12 * 60 * 60 * 1000;

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function sign(payload: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return toHex(await crypto.subtle.sign("HMAC", key, encoder.encode(payload)));
}

function timingSafeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

export async function signSession(expiresMs: number, secret: string): Promise<string> {
  const signature = await sign(`session:${expiresMs}`, secret);
  return `${expiresMs}.${signature}`;
}

export async function verifySession(token: string, secret: string): Promise<boolean> {
  const separator = token.indexOf(".");
  if (separator <= 0) return false;
  const expiresMs = Number(token.slice(0, separator));
  if (!Number.isSafeInteger(expiresMs) || Date.now() >= expiresMs) return false;
  const expected = await sign(`session:${expiresMs}`, secret);
  return timingSafeEqual(expected, token.slice(separator + 1));
}

export function readCookie(request: Request, name: string): string | null {
  const header = request.headers.get("cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() === name) {
      return part.slice(separator + 1).trim() || null;
    }
  }
  return null;
}
