import { useEffect, useState } from 'react';
import {
  ArrowLeft,
  FileText,
  Globe2,
  Hospital,
  KeyRound,
  Loader2,
  LockKeyhole,
  Mail,
  RotateCcw,
  ShieldCheck,
} from 'lucide-react';
import './login.css';

const API_BASE_URL = import.meta.env.VITE_API_URL || '';

export default function LoginPage({ onLoginSuccess }) {
  const [step, setStep] = useState('credentials');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [timer, setTimer] = useState(300);

  useEffect(() => {
    if (step !== 'otp' || timer <= 0) return undefined;
    const intervalId = window.setInterval(() => setTimer((current) => current - 1), 1000);
    return () => window.clearInterval(intervalId);
  }, [step, timer]);

  const formatTime = (seconds) => {
    const minutes = Math.floor(seconds / 60);
    const remainder = seconds % 60;
    return `${String(minutes).padStart(2, '0')}:${String(remainder).padStart(2, '0')}`;
  };

  const requestOtp = async () => {
    const response = await fetch(`${API_BASE_URL}/api/admin/login`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email.trim(), password }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || 'Unable to verify these credentials.');
    setStep('otp');
    setTimer(data.expires_in || 300);
    setOtpCode('');
  };

  const handleCredentialsSubmit = async (event) => {
    event.preventDefault();
    setError('');
    setLoading(true);
    try {
      await requestOtp();
    } catch (caught) {
      setError(caught.message);
    } finally {
      setLoading(false);
    }
  };

  const handleOtpSubmit = async (event) => {
    event.preventDefault();
    setError('');
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/api/admin/verify-otp`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: otpCode.trim() }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail || 'The verification code is not valid.');
      onLoginSuccess?.();
    } catch (caught) {
      setError(caught.message);
    } finally {
      setLoading(false);
    }
  };

  const handleResendOtp = async () => {
    setError('');
    setLoading(true);
    try {
      await requestOtp();
    } catch (caught) {
      setError(caught.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="login-shell">
      <section className="login-panel" aria-label="Healthcare SOC secure sign in">
        <div className="login-brand">
          <span className="login-brand-mark" aria-hidden="true"><Hospital size={28} /></span>
          <div>
            <p className="eyebrow">Restricted administrator access</p>
            <h1>Healthcare CTI SOC</h1>
          </div>
        </div>

        <div className="login-summary">
          <ShieldCheck size={20} />
          <span>Email, password, and one-time code are required to access security operations.</span>
        </div>

        {error && <div className="login-error" role="alert">{error}</div>}

        {step === 'credentials' ? (
          <form className="login-form" onSubmit={handleCredentialsSubmit}>
            <label>
              <span>Administrator email</span>
              <div className="input-shell">
                <Mail size={18} />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  placeholder="admin@hospital.com"
                  autoComplete="username"
                />
              </div>
            </label>
            <label>
              <span>Password</span>
              <div className="input-shell">
                <LockKeyhole size={18} />
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  placeholder="Enter administrator password"
                  autoComplete="current-password"
                />
              </div>
            </label>
            <button className="primary-action" type="submit" disabled={loading}>
              {loading ? <Loader2 className="spin" size={18} /> : <KeyRound size={18} />}
              Continue securely
            </button>
          </form>
        ) : (
          <form className="login-form" onSubmit={handleOtpSubmit}>
            <div className="otp-context">
              <p>Administrator identity verified</p>
              <strong>{email}</strong>
              <span>{timer > 0 ? `Verification window: ${formatTime(timer)}` : 'Code expired'}</span>
            </div>
            <label>
              <span>One-time verification code</span>
              <div className="input-shell otp-input-shell">
                <KeyRound size={18} />
                <input
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  maxLength="6"
                  required
                  value={otpCode}
                  onChange={(event) => setOtpCode(event.target.value.replace(/\D/g, ''))}
                  placeholder="000000"
                  autoComplete="one-time-code"
                />
              </div>
            </label>
            <button className="primary-action" type="submit" disabled={loading || timer <= 0}>
              {loading ? <Loader2 className="spin" size={18} /> : <ShieldCheck size={18} />}
              Verify and open SOC
            </button>
            <div className="login-secondary-actions">
              <button type="button" onClick={() => setStep('credentials')} className="ghost-action">
                <ArrowLeft size={16} /> Back
              </button>
              <button type="button" onClick={handleResendOtp} className="ghost-action" disabled={loading}>
                <RotateCcw size={16} /> Generate again
              </button>
            </div>
          </form>
        )}
      </section>

      <aside className="login-intel" aria-label="Protected security platform overview">
        <div>
          <p className="eyebrow">Protected security operations</p>
          <h2>Monitor hospital activity and investigate cyber threats from one secured platform.</h2>
        </div>
        <dl>
          <div><dt><ShieldCheck size={17} />Detection</dt><dd>CatBoost analysis of hospital and IoMT network flows</dd></div>
          <div><dt><Globe2 size={17} />Intelligence</dt><dd>OTX, VirusTotal, NVD, and OSV enrichment</dd></div>
          <div><dt><FileText size={17} />Response</dt><dd>Persisted alerts, recommendations, and incident reports</dd></div>
        </dl>
      </aside>
    </main>
  );
}
