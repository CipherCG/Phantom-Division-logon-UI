import { Router } from "express";
import { prisma } from "../prisma";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { generateRandomTokenHex, hashToken, signAccess } from "../utils/tokens";
import { authRateLimiter, strictAuthRateLimiter } from "../middleware/rateLimiter";

const router = Router();

// Config
const REFRESH_EXPIRES_DAYS = Number(process.env.REFRESH_TOKEN_EXPIRES_DAYS || 7);
const RESET_TOKEN_EXPIRES_MIN = Number(process.env.RESET_TOKEN_EXPIRES_MIN || 15);
const RESET_TOKEN_SECRET = process.env.JWT_RESET_SECRET || "reset_dev_secret";
const RECOVERY_LOCK_THRESHOLD = Number(process.env.RECOVERY_LOCK_THRESHOLD || 5);
const RECOVERY_LOCK_MINUTES = Number(process.env.RECOVERY_LOCK_MINUTES || 15);

// HELPER: create refresh token (opaque) and store hashed fingerprint
async function createRefreshToken(userId: number) {
  const token = generateRandomTokenHex(48);
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + REFRESH_EXPIRES_DAYS * 24 * 3600 * 1000);
  const rt = await prisma.refreshToken.create({
    data: { tokenHash, expiresAt, userId }
  });
  return { token, db: rt };
}

// Register
router.post("/register", authRateLimiter, async (req, res) => {
  const { email, password, fullName, recoveryQuestion, recoveryAnswer } = req.body;
  if (!email || !password) return res.status(400).json({ error: "email & password required" });

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) return res.status(409).json({ error: "User already exists" });

  const hash = await bcrypt.hash(password, 12);
  let recoveryAnswerHash: string | undefined = undefined;
  if (recoveryAnswer) {
    recoveryAnswerHash = await bcrypt.hash(recoveryAnswer, 12);
  }

  const user = await prisma.user.create({
    data: { email, passwordHash: hash, fullName, recoveryQuestion, recoveryAnswerHash }
  });

  const accessToken = signAccess(user.id);
  const refresh = await createRefreshToken(user.id);
  res.json({ user: { id: user.id, email: user.email, fullName: user.fullName }, accessToken, refreshToken: refresh.token });
});

// Login
router.post("/login", strictAuthRateLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "email & password required" });

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  const accessToken = signAccess(user.id);
  const refresh = await createRefreshToken(user.id);
  res.json({ user: { id: user.id, email: user.email, fullName: user.fullName }, accessToken, refreshToken: refresh.token });
});

// Refresh (rotate refresh token)
router.post("/refresh", authRateLimiter, async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: "refreshToken required" });

  const tokenHash = hashToken(refreshToken);
  const dbToken = await prisma.refreshToken.findFirst({ where: { tokenHash } });

  if (!dbToken || dbToken.revoked || dbToken.expiresAt < new Date()) {
    return res.status(401).json({ error: "Invalid refresh token" });
  }

  // rotate: create new token, mark current revoked and reference replacedBy
  const userId = dbToken.userId;
  const newRefresh = await createRefreshToken(userId);
  await prisma.refreshToken.update({
    where: { id: dbToken.id },
    data: { revoked: true, replacedById: newRefresh.db.id }
  });

  const accessToken = signAccess(userId);
  res.json({ accessToken, refreshToken: newRefresh.token });
});

// Revoke current refresh token (client can call to log out)
router.post("/revoke", authRateLimiter, async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: "refreshToken required" });
  const tokenHash = hashToken(refreshToken);
  await prisma.refreshToken.updateMany({ where: { tokenHash }, data: { revoked: true } });
  res.json({ ok: true });
});

// Initiate password reset by verifying recovery answer (no-email)
router.post("/initiate-reset", strictAuthRateLimiter, async (req, res) => {
  const { email, recoveryAnswer } = req.body;
  if (!email || !recoveryAnswer) return res.status(400).json({ error: "email & recoveryAnswer required" });

  const user = await prisma.user.findUnique({ where: { email } });
  // Generic message to avoid user enumeration
  if (!user || !user.recoveryAnswerHash) {
    return res.status(400).json({ error: "Invalid email or recovery answer" });
  }

  // Check lockout
  if (user.recoveryLockedUntil && user.recoveryLockedUntil > new Date()) {
    return res.status(429).json({ error: "Account recovery locked. Try again later." });
  }

  const ok = await bcrypt.compare(recoveryAnswer, user.recoveryAnswerHash);
  if (!ok) {
    // increment failed attempts
    const attempts = (user.failedRecoveryAttempts || 0) + 1;
    const data: any = { failedRecoveryAttempts: attempts };
    if (attempts >= RECOVERY_LOCK_THRESHOLD) {
      data.recoveryLockedUntil = new Date(Date.now() + RECOVERY_LOCK_MINUTES * 60 * 1000);
      data.failedRecoveryAttempts = 0; // reset counter after lock
    }
    await prisma.user.update({ where: { id: user.id }, data });
    return res.status(400).json({ error: "Invalid email or recovery answer" });
  }

  // success => reset failed attempts
  await prisma.user.update({ where: { id: user.id }, data: { failedRecoveryAttempts: 0, recoveryLockedUntil: null } });

  // create a reset token fingerprint + JWT that includes fingerprint
  const fingerprint = generateRandomTokenHex(16);
  const expiresAt = new Date(Date.now() + RESET_TOKEN_EXPIRES_MIN * 60 * 1000);
  await prisma.resetToken.create({ data: { fingerprint, expiresAt, userId: user.id } });

  const jwtToken = jwt.sign({ sub: user.id, purpose: "reset", f: fingerprint }, RESET_TOKEN_SECRET, { expiresIn: `${RESET_TOKEN_EXPIRES_MIN}m` });

  // return token directly (no email)
  return res.json({ resetToken: jwtToken, expiresIn: `${RESET_TOKEN_EXPIRES_MIN}m` });
});

// Reset password using reset token
router.post("/reset-password", strictAuthRateLimiter, async (req, res) => {
  const { resetToken, newPassword } = req.body;
  if (!resetToken || !newPassword) return res.status(400).json({ error: "resetToken and newPassword required" });

  try {
    const payload: any = jwt.verify(resetToken, RESET_TOKEN_SECRET);
    if (payload.purpose !== "reset") return res.status(400).json({ error: "Invalid token purpose" });

    const userId = Number(payload.sub);
    const fingerprint = payload.f as string;
    const tokenRecord = await prisma.resetToken.findUnique({ where: { fingerprint } });
    if (!tokenRecord || tokenRecord.revoked || tokenRecord.expiresAt < new Date() || tokenRecord.userId !== userId) {
      return res.status(400).json({ error: "Invalid or revoked reset token" });
    }

    const newHash = await bcrypt.hash(newPassword, 12);
    await prisma.user.update({ where: { id: userId }, data: { passwordHash: newHash } });

    // revoke the reset token so it cannot be reused
    await prisma.resetToken.update({ where: { fingerprint }, data: { revoked: true } });

    return res.json({ ok: true, message: "Password updated" });
  } catch (err) {
    return res.status(400).json({ error: "Invalid or expired reset token" });
  }
});

// Me endpoint (validate access token)
router.get("/me", authRateLimiter, async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) return res.status(401).json({ error: "Unauthorized" });
  const token = auth.substring(7);
  try {
    const payload: any = jwt.verify(token, process.env.JWT_ACCESS_SECRET || "access_dev_secret");
    if (payload.purpose !== "access") return res.status(401).json({ error: "Invalid token purpose" });
    const user = await prisma.user.findUnique({ where: { id: Number(payload.sub) } });
    if (!user) return res.status(401).json({ error: "Unauthorized" });
    res.json({ id: user.id, email: user.email, fullName: user.fullName });
  } catch (err) {
    res.status(401).json({ error: "Unauthorized" });
  }
});

export default router;