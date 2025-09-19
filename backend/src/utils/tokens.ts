import jwt from "jsonwebtoken";
import crypto from "crypto";

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || "access_dev_secret";
const ACCESS_EXPIRES = process.env.ACCESS_TOKEN_EXPIRES_IN || "15m";

export function signAccess(userId: number) {
  return jwt.sign({ sub: userId, purpose: "access" }, ACCESS_SECRET, { expiresIn: ACCESS_EXPIRES });
}

export function verifyAccess(token: string) {
  return jwt.verify(token, ACCESS_SECRET) as any;
}

export function generateRandomTokenHex(bytes = 48) {
  return crypto.randomBytes(bytes).toString("hex");
}

export function hashToken(token: string) {
  return crypto.createHash("sha256").update(token).digest("hex");
}