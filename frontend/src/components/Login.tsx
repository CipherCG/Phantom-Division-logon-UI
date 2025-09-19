import React, { useState } from "react";
import axios from "axios";
import ForgotPassword from "./ForgotPassword";

const API = import.meta.env.VITE_API_BASE_URL || "http://localhost:4000/api";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [showForgot, setShowForgot] = useState(false);

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setMessage(null);
    try {
      const res = await axios.post(`${API}/auth/login`, { email, password });
      // For demo we store the tokens in localStorage. In production use httpOnly cookies.
      localStorage.setItem("accessToken", res.data.accessToken);
      localStorage.setItem("refreshToken", res.data.refreshToken);
      setMessage(`Welcome back, ${res.data.user.fullName || res.data.user.email}`);
    } catch (err: any) {
      setMessage(err?.response?.data?.error || "Login failed");
    } finally {
      setLoading(false);
    }
  }

  if (showForgot) {
    return <ForgotPassword onBack={() => setShowForgot(false)} />;
  }

  return (
    <div className="login-screen">
      <div className="login-card">
        <div className="brand">
          <div className="logo">PHANTOM</div>
          <div className="subtitle">Division Logon</div>
        </div>

        <form onSubmit={handleLogin} className="form">
          <label className="label">
            Email
            <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          </label>
          <label className="label">
            Password
            <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          </label>

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <button className="btn" type="submit" disabled={loading}>
              {loading ? "Signing in..." : "Sign in"}
            </button>
            <button type="button" onClick={() => setShowForgot(true)} style={{ background: "transparent", border: "none", color: "#9aa6b2", cursor: "pointer" }}>
              Forgot?
            </button>
          </div>

          {message && <div className="message">{message}</div>}
        </form>
      </div>
    </div>
  );
}