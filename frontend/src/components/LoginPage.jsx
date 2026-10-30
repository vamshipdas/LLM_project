import React, { useState } from 'react';
import { ShieldAlert, LogIn, AlertTriangle, LockKeyhole, BookOpenCheck, Activity } from 'lucide-react';
import { login } from '../api';

export default function LoginPage({ onLoggedIn }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setError('Enter both your username and password.');
      return;
    }
    setIsSubmitting(true);
    setError('');
    try {
      const authenticatedUser = await login(username.trim(), password);
      onLoggedIn(authenticatedUser);
    } catch (err) {
      setError(err.message || 'Sign in failed.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <main className="login-shell">
      <section className="login-intro">
        <div className="login-mark"><ShieldAlert size={26} /></div>
        <div className="eyebrow"><span className="status-dot" /> Secure operations workspace</div>
        <h1>Move from alert to action with confidence.</h1>
        <p>Search approved playbooks, preserve investigation context, and coordinate the next response step from one focused console.</p>
        <div className="login-features">
          <span><BookOpenCheck size={16} /> SOP-grounded guidance</span>
          <span><Activity size={16} /> Live incident context</span>
          <span><LockKeyhole size={16} /> Role-based access</span>
        </div>
      </section>
      <section className="cyber-card login-card">
        <div className="eyebrow">Analyst access</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginBottom: '8px' }}>
          <div style={{
            background: 'linear-gradient(135deg, rgba(56, 189, 248, 0.2), rgba(168, 85, 247, 0.2))',
            border: '1px solid rgba(56, 189, 248, 0.4)',
            padding: '10px',
            borderRadius: '12px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <ShieldAlert size={26} color="#38bdf8" />
          </div>
          <div>
            <h2 style={{ fontSize: '1.1rem', fontWeight: 800, color: '#f8fafc', letterSpacing: '-0.02em' }}>
              Welcome back
            </h2>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Sign in to your response workspace
            </p>
          </div>
        </div>

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div className="field-group">
            <label
              htmlFor="username"
              style={{ fontSize: '0.78rem', color: 'var(--text-dim)', fontWeight: 600, display: 'block', marginBottom: '6px' }}
            >
              Username
            </label>
            <input
              id="username"
              type="text"
              autoComplete="username"
              required
              placeholder="analyst"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              style={{
                width: '100%', background: '#090d16',
                border: '1px solid rgba(255, 255, 255, 0.1)', borderRadius: '8px',
                padding: '9px 12px', color: '#f8fafc', outline: 'none'
              }}
            />
          </div>
          <div className="field-group">
            <label
              htmlFor="password"
              style={{ fontSize: '0.78rem', color: 'var(--text-dim)', fontWeight: 600, display: 'block', marginBottom: '6px' }}
            >
              Password
            </label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              required
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              style={{
                width: '100%', background: '#090d16',
                border: '1px solid rgba(255, 255, 255, 0.1)', borderRadius: '8px',
                padding: '9px 12px', color: '#f8fafc', outline: 'none'
              }}
            />
          </div>
          {error && (
            <div style={{
              background: 'rgba(251, 113, 133, 0.12)',
              border: '1px solid rgba(251, 113, 133, 0.4)',
              padding: '10px 14px', borderRadius: '8px', color: '#fb7185',
              fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '8px'
            }}>
              <AlertTriangle size={16} /> {error}
            </div>
          )}
          <button
            type="submit"
            disabled={isSubmitting}
            className="btn btn-primary"
            style={{ marginTop: '4px' }}
          >
            <LogIn size={16} />
            {isSubmitting ? 'Signing in…' : 'Sign In'}
          </button>
        </form>
        <div className="demo-note">
          Demo users: <strong>admin</strong> or <strong>analyst</strong>
        </div>
      </section>
    </main>
  );
}
