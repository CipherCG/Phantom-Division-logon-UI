```markdown
# Phanton Division Logon UI

Full-stack recreation of the Phantom Division logon UI with an authentication backend and SQL (Postgres) database.

Stack:
- Frontend: React + Vite + TypeScript
- Backend: Node.js + Express + TypeScript
- Database: PostgreSQL + Prisma
- Auth: bcrypt, JWT (access), opaque refresh tokens with rotation, reset tokens with DB fingerprints
- Dev infra: Docker Compose for Postgres + Adminer

Security features included:
- Rate limiting on auth endpoints
- Refresh token rotation & revocation (stored as hashed fingerprints)
- Reset token issuance with DB-stored fingerprint (immediate revocation)
- Account lockout for multiple failed recovery attempts
- Recovery-question-based password reset (no email)

See INSTRUCTIONS.md for full setup and verification steps.
```