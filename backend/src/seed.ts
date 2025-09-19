import { prisma } from "./prisma";
import bcrypt from "bcrypt";
import { generateRandomTokenHex, hashToken } from "./utils/tokens";

async function main() {
  const passwordHash = await bcrypt.hash("Pa$$w0rd", 12);
  const recoveryAnswerHash = await bcrypt.hash("blue", 12); // example answer

  const user = await prisma.user.upsert({
    where: { email: "admin@phantom.local" },
    update: {},
    create: {
      email: "admin@phantom.local",
      passwordHash,
      fullName: "Phantom Admin",
      recoveryQuestion: "What's your favorite color?",
      recoveryAnswerHash
    }
  });
  console.log("Seeded default user: admin@phantom.local / Pa$$w0rd (recovery answer: blue)");

  // create one refresh token for convenience/testing (not recommended for production)
  const refreshToken = generateRandomTokenHex(48);
  const tokenHash = hashToken(refreshToken);
  const expiresAt = new Date(Date.now() + Number(process.env.REFRESH_TOKEN_EXPIRES_DAYS || 7) * 24 * 3600 * 1000);
  await prisma.refreshToken.create({
    data: { tokenHash, userId: user.id, expiresAt }
  });
  console.log("Seeded a refresh token (store this if you need it):", refreshToken);
}

main()
  .catch((e) => console.error(e))
  .finally(() => prisma.$disconnect());