```markdown
# Run & Verify locally

Prereqs:
- Node.js 18+
- Docker & Docker Compose
- Git & GitHub CLI (optional but recommended)

Repository name suggested: Phanton-Division-Logon-UI
Branch for changes: feat/auth-hardening

1) Create the GitHub repo (example using gh)
   gh repo create "CipherCG/Phanton-Division-Logon-UI" --public --confirm

2) Clone it locally:
   git clone git@github.com:CipherCG/Phanton-Division-Logon-UI.git
   cd Phanton-Division-Logon-UI

3) Create branch and add files:
   git checkout -b feat/auth-hardening
   # add files from this package into appropriate folders (backend/, frontend/, prisma/, etc)
   git add .
   git commit -m "feat: add full-stack Phantom Division logon UI + auth hardening (rate-limiting, token revocation, recovery flow)"
   git push -u origin feat/auth-hardening

4) Create the DB (Docker)
   docker-compose up -d

5) Backend setup
   cd backend
   cp ../.env.example .env
   # edit .env and set strong JWT secrets (JWT_ACCESS_SECRET, JWT_RESET_SECRET)
   npm install
   npx prisma generate
   npx prisma migrate dev --name init
   npm run seed
   npm run dev

6) Frontend setup
   cd ../frontend
   npm install
   npm run dev
   # open http://localhost:5173

7) Verify the flows
   - Login with seeded user:
     email: admin@phantom.local
     password: Pa$$w0rd
     recovery question: "What's your favorite color?"
     recovery answer: blue

   - Test forgot password:
     - Click "Forgot?" > enter email and recovery answer > receive reset token > set new password
     - After reset, sign in using the new password.

8) Create a PR (after pushing branch)
   gh pr create --title "Add full-stack Phantom Division logon UI + auth hardening (rate-limiting, token revocation, recovery flow)" --body-file pr_body.md --base main

Notes and recommendations
- In production, store refresh tokens as httpOnly secure cookies, and never return tokens directly to the client in localStorage.
- Rotate JWT secrets regularly and use long random secrets for JWT_*_SECRET.
- Harden rate-limit and lockout thresholds as appropriate for your user base.
- Consider adding MFA for account recovery and more advanced identity checks.
```