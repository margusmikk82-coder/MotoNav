const DEFAULT_USER = "MarguS";
const DEFAULT_PASS = "MinuViP2026";

export const config = {
  matcher: "/(.*)"
};

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const maxLen = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < maxLen; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}

function unauthorizedResponse() {
  return new Response("Autentimine nõutud", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="MotoNav", charset="UTF-8"',
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

export default function middleware(request) {
  const expectedUser =
    (typeof process !== "undefined" && process.env && process.env.BASIC_AUTH_USER) || DEFAULT_USER;
  const expectedPass =
    (typeof process !== "undefined" && process.env && process.env.BASIC_AUTH_PASSWORD) || DEFAULT_PASS;

  const authHeader = request.headers.get("authorization");
  if (!authHeader) {
    return unauthorizedResponse();
  }

  const match = authHeader.match(/^Basic\s+(.+)$/i);
  if (!match) {
    return unauthorizedResponse();
  }

  let decoded = "";
  try {
    decoded = atob(match[1].trim());
  } catch (_) {
    return unauthorizedResponse();
  }

  const sepIdx = decoded.indexOf(":");
  if (sepIdx === -1) {
    return unauthorizedResponse();
  }

  const user = decoded.slice(0, sepIdx);
  const pass = decoded.slice(sepIdx + 1);

  if (!safeEqual(user, expectedUser) || !safeEqual(pass, expectedPass)) {
    return unauthorizedResponse();
  }

  return new Response(null, {
    headers: {
      "x-middleware-next": "1"
    }
  });
}
