import { t, useLocale } from "../i18n/language";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { FaChartLine, FaCheck, FaEnvelope, FaEye, FaEyeSlash, FaLock, FaShieldAlt, FaTimesCircle } from "react-icons/fa";
import { useAuth } from "../context/auth-context";
import "./Login.css";
export default function Login() {
  useLocale();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [loginSucceeded, setLoginSucceeded] = useState(false);
  const [loginRejected, setLoginRejected] = useState(false);
  const {
    login
  } = useAuth();
  const navigate = useNavigate();
  const handleSubmit = async event => {
    event.preventDefault();
    setError("");
    setLoginRejected(false);
    setLoading(true);
    try {
      await login(email, password);
      setLoginSucceeded(true);
      await new Promise(resolve => window.setTimeout(resolve, 1100));
      navigate("/dashboard");
    } catch (requestError) {
      setLoginRejected(true);
      const status = requestError.response?.status;
      const unavailable = !requestError.response || status >= 500;
      setError(unavailable
        ? "The sign-in service is unavailable. Open SentinelX using the launcher and retry."
        : requestError.response?.data?.error || "Unable to sign in. Check your credentials and try again.");
    } finally {
      setLoading(false);
    }
  };
  return <main className="loginPage">
      {loginSucceeded && <div className="loginSuccessOverlay" role="status" aria-live="polite">
          <div className="loginSuccessPulse" aria-hidden="true" />
          <div className="loginSuccessCard">
            <div className="loginSuccessShield">
              <FaShieldAlt />
              <span><FaCheck /></span>
            </div>
            <p>{t("IDENTITY VERIFIED")}</p>
            <h2>{t("Access Granted")}</h2>
            <small>{t("Opening your SentinelX workspace...")}</small>
            <div className="loginSuccessProgress"><span /></div>
          </div>
        </div>}
      <div className="loginGlow loginGlow--one" />
      <div className="loginGlow loginGlow--two" />
      <div className="loginBackdropWord" aria-hidden="true">SentinelX</div>
      <div className="loginParticles" aria-hidden="true">
        {Array.from({
        length: 8
      }, (_, index) => <span key={index} />)}
      </div>

      <section className="loginShell">
        <div className="loginIntro">
          <div className="loginBrand">
            <span className="loginBrand__shield"><FaShieldAlt /></span>
            <div>
              <h1>SentinelX</h1>
              <p>{t("Security Operations Center")}</p>
            </div>
          </div>

          <div className="loginOrbit" aria-hidden="true">
            <span /><span /><span />
            <FaShieldAlt />
          </div>

          <p className="loginIntro__eyebrow">{t("VULNERABILITY MANAGEMENT")}</p>
          <h2>{t("See your security posture clearly.")}</h2>
          <p className="loginIntro__description">{t("Centralize security scans, prioritize findings, and review actionable remediation guidance from one protected workspace.")}</p>

          <div className="loginFeatures">
            <div><FaShieldAlt /><span><strong>{t("Integrated Scanning")}</strong><small>{t("Nmap, ZAP, Nuclei, and WhatWeb")}</small></span></div>
            <div><FaChartLine /><span><strong>{t("Unified Visibility")}</strong><small>{t("Findings, history, and reports in one place")}</small></span></div>
            <div><FaLock /><span><strong>{t("Authorized Workspace")}</strong><small>{t("JWT-protected access to security data")}</small></span></div>
          </div>
        </div>

        <div className="loginCardWrap">
          <form className={`loginCard${loginRejected ? " loginCard--rejected" : ""}`} onSubmit={handleSubmit}>
            <div className="loginCard__header">
              <span className="loginCard__icon"><FaLock /></span>
              <p>{t("WELCOME BACK")}</p>
              <h2>{t("Sign in to SentinelX")}</h2>
              <span>{t("Use your authorized account to continue.")}</span>
            </div>

            {t(error) && <div className="loginError" role="alert"><FaTimesCircle />{t(error)}</div>}

            <label className="loginField">
              <span>{t("Email address")}</span>
              <div className="loginInputWrap">
                <FaEnvelope />
                <input id="login-email" name="email" type="email" value={email} onChange={event => setEmail(event.target.value)} placeholder={t("name@example.com")} autoComplete="username" spellCheck="false" required />
              </div>
            </label>

            <label className="loginField">
              <span>{t("Password")}</span>
              <div className="loginInputWrap">
                <FaLock />
                <input id="login-password" name="password" type={showPassword ? "text" : "password"} value={password} onChange={event => setPassword(event.target.value)} placeholder={t("Enter your password")} autoComplete="current-password" required />
                <button type="button" className="passwordToggle" onClick={() => setShowPassword(visible => !visible)} aria-label={t(showPassword ? t("Hide password") : t("Show password"))}>
                  {showPassword ? <FaEyeSlash /> : <FaEye />}
                </button>
              </div>
            </label>

            <div className="loginForgot"><Link to="/forgot-password">{t("Forgot password?")}</Link></div>

            <button className="loginButton" type="submit" disabled={loading}>
              {loading ? <><span className="loginSpinner" />{t("Please wait...")}</> : t("Sign In")}
            </button>

            <p className="loginRegister">{t("New to SentinelX? ")}<Link to="/register">{t("Create an account")}</Link>
            </p>

            <div className="loginPrivacy">
              <FaLock />
              <span>{t("Private workspace \xB7 Authorized access only")}</span>
            </div>
          </form>
        </div>
      </section>
    </main>;
}
