import { useEffect, useState } from 'react';
import { ArrowLeft, Hospital, KeyRound, Loader2, LockKeyhole, Mail, RotateCcw, ShieldCheck } from 'lucide-react';
import './login.css';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

export default function LoginPage({ onLoginSuccess }) {
  const [step, setStep] = useState('credentials');
  const [email, setEmail] = useState('admin@hospital.com');
  const [password, setPassword] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [timer, setTimer] = useState(300);

  useEffect(() => {
    if (step !== 'otp' || timer <= 0) {
      return undefined;
    }

    const intervalId = window.setInterval(() => {
      setTimer((current) => current - 1);
    }, 1000);

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
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email.trim(), password }),
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new Error(data.detail || 'Unable to verify these credentials.');
    }

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
    } catch (err) {
      setError(err.message);
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
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email.trim(), code: otpCode.trim() }),
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(data.detail || 'The verification code is not valid.');
      }

      onLoginSuccess?.();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleResendOtp = async () => {
    setError('');
    setLoading(true);

    try {
      await requestOtp();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="login-shell">
      <section className="login-panel" aria-label="Healthcare SOC sign in">
        <div className="login-brand">
          <span className="login-brand-mark" aria-hidden="true">
            <Hospital size={28} />
          </span>
          <div>
            <p className="eyebrow">University Hospital</p>
            <h1>Healthcare CTI SOC</h1>
          </div>
        </div>

        <div className="login-summary">
          <ShieldCheck size={20} />
          <span>Threat intelligence console with OTP protected access.</span>
        </div>

        {error && (
          <div className="login-error" role="alert">
            {error}
          </div>
        )}

        {step === 'credentials' ? (
          <form className="login-form" onSubmit={handleCredentialsSubmit}>
            <label>
              <span>Email</span>
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
                  placeholder="Enter admin password"
                  autoComplete="current-password"
                />
              </div>
            </label>

            <button className="primary-action" type="submit" disabled={loading}>
              {loading ? <Loader2 className="spin" size={18} /> : <KeyRound size={18} />}
              Continue
            </button>
          </form>
        ) : (
          <form className="login-form" onSubmit={handleOtpSubmit}>
            <div className="otp-context">
              <p>Verification code sent for</p>
              <strong>{email}</strong>
              <span>{timer > 0 ? `Expires in ${formatTime(timer)}` : 'Code expired'}</span>
            </div>

            <label>
              <span>One-time code</span>
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
              Verify and Open Dashboard
            </button>

            <div className="login-secondary-actions">
              <button type="button" onClick={() => setStep('credentials')} className="ghost-action">
                <ArrowLeft size={16} />
                Back
              </button>
              <button type="button" onClick={handleResendOtp} className="ghost-action" disabled={loading}>
                <RotateCcw size={16} />
                Resend
              </button>
            </div>
          </form>
        )}
      </section>

      <aside className="login-intel" aria-label="Security highlights">
        <div>
          <p className="eyebrow">Live posture</p>
          <h2>Monitor patient, environment, and attack telemetry in one place.</h2>
        </div>
        <dl>
          <div>
            <dt>TLP</dt>
            <dd>Automated traffic handling labels</dd>
          </div>
          <div>
            <dt>OTX</dt>
            <dd>Indicator matching for suspicious destinations</dd>
          </div>
          <div>
            <dt>Reports</dt>
            <dd>Printable incident summaries for triage</dd>
          </div>
        </dl>
      </aside>
    </main>
  );
}
