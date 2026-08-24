import { useEffect, useState } from 'react';
import LoginPage from './LoginPage';
import Dashboard from './dashboard.jsx';

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(null);

  useEffect(() => {
    let active = true;
    const checkSession = async () => {
      try {
        const response = await fetch('/api/admin/session', { credentials: 'include' });
        const payload = await response.json();
        if (active) setIsAuthenticated(Boolean(payload.authenticated));
      } catch {
        if (active) setIsAuthenticated(false);
      }
    };
    checkSession();
    const intervalId = window.setInterval(checkSession, 60_000);
    return () => {
      active = false;
      window.clearInterval(intervalId);
    };
  }, []);

  const handleLogout = async () => {
    try {
      await fetch('/api/admin/logout', { method: 'POST', credentials: 'include' });
    } finally {
      setIsAuthenticated(false);
    }
  };

  if (isAuthenticated === null) {
    return <main className="auth-loading" aria-label="Checking secure session">Checking secure session…</main>;
  }

  if (!isAuthenticated) {
    return <LoginPage onLoginSuccess={() => setIsAuthenticated(true)} />;
  }

  return <Dashboard onLogout={handleLogout} />;
}
