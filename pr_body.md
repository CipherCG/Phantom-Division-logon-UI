```markdown
# Add full-stack Phantom Division logon UI + auth hardening (rate-limiting, token revocation, recovery flow)

Summary:
- Adds a complete full-stack project that recreates the Phantom Division logon UI and implements secure authentication backed by PostgreSQL (Prisma).
- Security hardening included:
  - Rate-limiting on auth endpoints (configurable via env)
  - Refresh token rotation & storage as hashed fingerprints (revocable)
  - Reset token issuance with DB-stored fingerprint (revocable)
  - Account lockout for repeated failed recovery attempts
  - Recovery-question-based password recovery (no email), with hashed recovery answers
- Includes docker-compose.yml for Postgres + Adminer, Prisma schema & models, seed script with demo user, and a Vite React frontend.

How to run: See INSTRUCTIONS.md

Security notes:
- For production, use httpOnly secure cookies for tokens and additional identity checks for account recovery.
- Replace all JWT secrets with long random strings before deploying.
- Configure sensible rate-limit thresholds and consider a WAF/reverse proxy.

Files added:
- docker-compose.yml
- backend/ (packages, src, prisma)
- frontend/ (packages, src)
- prisma/schema.prisma
- README.md and INSTRUCTIONS.md
```