import React, { useState } from "react";
import axios from "axios";

const API = import.meta.env.VITE_API_BASE_URL || "http://localhost:4000/api";

export default function ForgotPassword({ onBack }: { onBack: () => void }) {
  const [step, setStep] = useState<1 | 2>(1);
  const [email, setEmail] = useState("");
  const [recoveryAnswer, setRecoveryAnswer] = useState("");
  const [resetToken, setResetToken] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleInitiate(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setMessage(null);
    try {
      const res = await axios.post(`${API}/auth/initiate-reset`, { email, recoveryAnswer });
      setResetToken(res.data.resetToken);
      setMessage(`Reset token issued (expires in ${res.data.expiresIn}). Use it to set a new password.`);
      setStep(2);
    } catch (err: any) {
      setMessage(err?.response?.data?.error || "Failed to verify recovery info");
    } finally {
      setLoading(false);
    }
  }

  async function handleReset(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setMessage(null);
    try {
      const payload = { resetToken, newPassword };
      await axios.post(`${API}/auth/reset-password`, payload);
      setMessage("Password successfully reset. You can sign in with your new password.");
    } catch (err: any) {
      setMessage(err?.response?.data?.error || "Failed to reset password");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-card">
      <div style={{ textAlign: "center", marginBottom: 12 }}>
        <div style={{ fontWeight: 700, color: "#6ee7b7" }}>Password Recovery</div>
        <div style={{ color: "#9aa6b2", marginTop: 6 }}>Verify using your recovery answer</div>
      </div>

      {step === 1 && (
        <form onSubmit={handleInitiate} className="form">
          <label className="label">
            Email (account)
            <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          </label>
          <label className="label">
            Recovery Answer
            <input className="input" type="text" value={recoveryAnswer} onChange={(e) => setRecoveryAnswer(e.target.value)} required />
          </label>

          <div style={{ display: "flex", gap: 8 }}>
            <button className="btn" type="submit" disabled={loading}>
              {loading ? "Verifying..." : "Verify"}
            </button>
            <button type="button" onClick={onBack} style={{ background: "transparent", border: "none", color: "#9aa6b2", cursor: "pointer" }}>
              Back
            </button>
          </div>

          {message && <div className="message">{message}</div>}
        </form>
      )}

      {step === 2 && (
        <form onSubmit={handleReset} className="form">
          <label className="label">
            Reset Token (auto-filled)
            <input className="input" value={resetToken} onChange={(e) => setResetToken(e.target.value)} />
          </label>
          <label className="label">
            New Password
            <input className="input" type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} required />
          </label>

          <div style={{ display: "flex", gap: 8 }}>
            <button className="btn" type="submit" disabled={loading}>
              {loading ? "Resetting..." : "Set New Password"}
            </button>
            <button type="button" onClick={() => setStep(1)} style={{ background: "transparent", border: "none", color: "#9aa6b2", cursor: "pointer" }}>
              Back
            </button>
          </div>

          {message && <div className="message">{message}</div>}
        </form>
      )}
    </div>
  );
}