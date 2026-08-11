import { timingSafeEqual } from "node:crypto";

export function base64UrlEncode(value) {
  const buffer = Buffer.isBuffer(value) ? value : Buffer.from(value);
  return buffer.toString("base64url");
}

export function base64UrlDecode(value) {
  if (typeof value !== "string" || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new TypeError("Invalid base64url value");
  }
  const decoded = Buffer.from(value, "base64url");
  if (base64UrlEncode(decoded) !== value.replace(/=+$/u, "")) {
    throw new TypeError("Non-canonical base64url value");
  }
  return decoded;
}

export function decodeBase64(value) {
  if (typeof value !== "string" || value.length === 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new TypeError("Invalid base64 value");
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64").replace(/=+$/u, "") !== value.replace(/=+$/u, "")) {
    throw new TypeError("Non-canonical base64 value");
  }
  return decoded;
}

export function constantTimeEqual(left, right) {
  const leftBuffer = Buffer.isBuffer(left) ? left : Buffer.from(left);
  const rightBuffer = Buffer.isBuffer(right) ? right : Buffer.from(right);
  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }
  return timingSafeEqual(leftBuffer, rightBuffer);
}
