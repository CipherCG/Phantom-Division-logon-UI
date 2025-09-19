import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import authRouter from "./routes/auth";

dotenv.config();

const app = express();
app.use(cors({ origin: true }));
app.use(express.json());

app.use("/api/auth", authRouter);

app.get("/api/health", (req, res) => res.json({ ok: true }));

const port = Number(process.env.PORT || 4000);
app.listen(port, () => {
  console.log(`Backend listening on http://localhost:${port}`);
});