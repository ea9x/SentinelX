import { t, useLocale } from "../i18n/language";
import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/auth-context';
export default function Register() {
  useLocale();
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const {
    register
  } = useAuth();
  const navigate = useNavigate();
  const handleSubmit = async e => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setLoading(true);
    try {
      await register(username, email, password);
      setSuccess('Account created successfully! Redirecting to sign in...');
      setTimeout(() => navigate('/login'), 1500);
    } catch (err) {
      setError(err.response?.data?.error || 'Something went wrong. Please try again.');
    } finally {
      setLoading(false);
    }
  };
  return <div style={styles.container}>
            <form onSubmit={handleSubmit} style={styles.form}>
                <h1 style={styles.title}>{t("\uD83D\uDEE1\uFE0F SentinelX")}</h1>
                <p style={styles.subtitle}>{t("Create a new account")}</p>

                {t(error) && <div style={styles.error}>{t(error)}</div>}
                {success && <div style={styles.success}>{success}</div>}

                <input type="text" placeholder={t("Username")} value={username} onChange={e => setUsername(e.target.value)} required style={styles.input} />
                <input type="email" placeholder={t("Email address")} value={email} onChange={e => setEmail(e.target.value)} required style={styles.input} />
                <input type="password" placeholder={t("Password")} value={password} onChange={e => setPassword(e.target.value)} required style={styles.input} />

                <button type="submit" disabled={loading} style={styles.button}>
                    {loading ? t("Creating account...") : t("Create Account")}
                </button>

                <p style={styles.linkText}>{t("Already have an account? ")}<Link to="/login" style={styles.link}>{t("Sign In")}</Link>
                </p>
            </form>
        </div>;
}
const styles = {
  container: {
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    height: '100vh',
    backgroundColor: '#0f172a'
  },
  form: {
    backgroundColor: '#1e293b',
    padding: '40px',
    borderRadius: '12px',
    width: '350px',
    boxShadow: '0 10px 30px rgba(0,0,0,0.5)',
    direction: 'ltr'
  },
  title: {
    color: '#38bdf8',
    textAlign: 'center',
    marginBottom: '5px'
  },
  subtitle: {
    color: '#94a3b8',
    textAlign: 'center',
    marginBottom: '20px'
  },
  input: {
    width: '100%',
    padding: '12px',
    marginBottom: '15px',
    borderRadius: '8px',
    border: '1px solid #334155',
    backgroundColor: '#0f172a',
    color: 'white',
    fontSize: '14px',
    boxSizing: 'border-box'
  },
  button: {
    width: '100%',
    padding: '12px',
    borderRadius: '8px',
    border: 'none',
    backgroundColor: '#38bdf8',
    color: '#0f172a',
    fontWeight: 'bold',
    cursor: 'pointer',
    fontSize: '15px'
  },
  error: {
    backgroundColor: '#7f1d1d',
    color: '#fecaca',
    padding: '10px',
    borderRadius: '8px',
    marginBottom: '15px',
    fontSize: '13px',
    textAlign: 'center'
  },
  success: {
    backgroundColor: '#14532d',
    color: '#bbf7d0',
    padding: '10px',
    borderRadius: '8px',
    marginBottom: '15px',
    fontSize: '13px',
    textAlign: 'center'
  },
  linkText: {
    color: '#94a3b8',
    textAlign: 'center',
    marginTop: '15px',
    fontSize: '13px'
  },
  link: {
    color: '#38bdf8',
    textDecoration: 'none'
  }
};
