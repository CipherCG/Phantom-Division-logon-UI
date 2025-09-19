import rateLimit from "express-rate-limit";

const windowMs = Number(process.env.RATE_LIMIT_WINDOW_MS || 60_000); // default 1 minute
const max = Number(process.env.RATE_LIMIT_MAX || 8); // default 8 requests per window

export const authRateLimiter = rateLimit({
  windowMs,
  max,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, please try again later." }
});

// stricter limiter for sensitive endpoints (login, initiate-reset)
export const strictAuthRateLimiter = rateLimit({
  windowMs,
  max: Number(process.env.RATE_LIMIT_STRICT_MAX || 5),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, slow down." }
});