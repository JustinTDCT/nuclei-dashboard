import { FormEvent, useState } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../auth";

export function Login() {
  const { user, login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  if (user) return <Navigate to="/" replace />;

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await login(username, password);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-screen grid place-items-center bg-[radial-gradient(circle_at_top,_#164e63_0,_#020617_50%)]">
      <form onSubmit={onSubmit} className="w-full max-w-sm bg-slate-900/80 border border-slate-800 rounded-xl p-8 space-y-4">
        <div>
          <div className="text-xs uppercase tracking-[0.2em] text-cyan-400">Nuclei</div>
          <h1 className="text-2xl font-semibold">Staff sign in</h1>
          <p className="text-sm text-slate-400 mt-1">Internal control plane for client scans.</p>
        </div>
        <div>
          <label>Username</label>
          <input className="w-full" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
        </div>
        <div>
          <label>Password</label>
          <input className="w-full" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>
        {error && <div className="text-sm text-rose-300">{error}</div>}
        <button
          className="w-full bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-medium rounded-md py-2"
          disabled={busy}
        >
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
