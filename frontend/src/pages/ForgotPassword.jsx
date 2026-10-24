import { t, useLocale } from "../i18n/language";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { FaCheck, FaEnvelope, FaEye, FaEyeSlash, FaKey, FaLock, FaShieldAlt, FaTimesCircle } from "react-icons/fa";
import api from "../api/axios";
import "./Login.css";
export default function ForgotPassword() {
  useLocale();
  const [email, setEmail] = useState("");
  const [token, setToken] = useState(() => new URLSearchParams(window.location.hash.slice(1)).get("token") || "");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [loading, setLoading] = useState(false);
  const [complete, setComplete] = useState(false);
  const navigate = useNavigate();
  const requestLink = async event => {
    event.preventDefault();
    setError("");
    setLoading(true);
    try {
      const response = await api.post("/auth/password/forgot", {
        email
      });
      setNotice(response.data.message);
    } catch (requestError) {
      setError(requestError.response?.data?.error || "Unable to request a reset link.");
    } finally {
      setLoading(false);
    }
  };
  const resetPassword = async event => {
    event.preventDefault();
    setError("");
    if (password !== confirmPassword) {
      setError("The passwords do not match.");
      return;
    }
    setLoading(true);
    try {
      await api.post("/auth/password/reset", {
        token,
        new_password: password
      });
      window.history.replaceState(null, "", window.location.pathname);
      setComplete(true);
      window.setTimeout(() => navigate("/login"), 1800);
    } catch (requestError) {
      setError(requestError.response?.data?.error || "Unable to reset the password.");
    } finally {
      setLoading(false);
    }
  };
  return <main className="loginPage">
      {complete && <div className="loginSuccessOverlay" role="status">
        <div className="loginSuccessCard">
          <div className="loginSuccessShield"><FaShieldAlt /><span><FaCheck /></span></div>
          <p>{t("PASSWORD UPDATED")}</p><h2>{t("Access Restored")}</h2>
          <small>{t("Returning you to secure sign in...")}</small>
        </div>
      </div>}
      <div className="loginGlow loginGlow--one" /><div className="loginGlow loginGlow--two" />
      <section className="loginShell loginShell--recovery">
        <div className="loginIntro">
          <div className="loginBrand"><span className="loginBrand__shield"><FaShieldAlt /></span><div><h1>SentinelX</h1><p>{t("Account Recovery")}</p></div></div>
          <p className="loginIntro__eyebrow">{t("SECURE PASSWORD RECOVERY")}</p>
          <h2>{t("Recover access safely.")}</h2>
          <p className="loginIntro__description">{t("We verify ownership through your registered email before allowing a password change.")}</p>
        </div>
        <div className="loginCardWrap">
          <form className="loginCard" onSubmit={token ? resetPassword : requestLink}>
            <div className="loginCard__header">
              <span className="loginCard__icon"><FaKey /></span>
              <p>{t("ACCOUNT RECOVERY")}</p>
              <h2>{token ? t("Create a new password") : t("Forgot your password?")}</h2>
              <span>{token ? t("Choose a secure password to complete your reset.") : t("Enter your registered email to receive a reset link.")}</span>
            </div>
            {t(error) && <div className="loginError" role="alert"><FaTimesCircle />{t(error)}</div>}
            {notice && <div className="loginNotice" role="status">{notice}</div>}
            {!token ? <label className="loginField"><span>{t("Email address")}</span><div className="loginInputWrap"><FaEnvelope /><input type="email" value={email} onChange={event => setEmail(event.target.value)} autoComplete="email" placeholder={t("name@example.com")} required autoFocus /></div></label> : <>
              <label className="loginField"><span>{t("New password")}</span><div className="loginInputWrap"><FaLock /><input type={showPassword ? "text" : "password"} value={password} onChange={event => setPassword(event.target.value)} minLength="8" autoComplete="new-password" placeholder={t("At least 8 characters")} required /><button type="button" className="passwordToggle" onClick={() => setShowPassword(value => !value)} aria-label={t("Toggle password visibility")}>{showPassword ? <FaEyeSlash /> : <FaEye />}</button></div></label>
              <label className="loginField"><span>{t("Confirm new password")}</span><div className="loginInputWrap"><FaLock /><input type={showPassword ? "text" : "password"} value={confirmPassword} onChange={event => setConfirmPassword(event.target.value)} minLength="8" autoComplete="new-password" placeholder={t("Repeat your new password")} required /></div></label>
            </>}
            <button className="loginButton" type="submit" disabled={loading}>{loading ? <><span className="loginSpinner" />{t("Please wait...")}</> : token ? t("Reset Password") : t("Send Reset Link")}</button>
            {token && <div className="loginOtpActions"><button type="button" onClick={() => {
              setToken("");
              window.history.replaceState(null, "", window.location.pathname);
              setNotice("");
              setError("");
            }}>{t("Request another link")}</button></div>}
            <p className="loginRegister"><Link to="/login">{t("Back to sign in")}</Link></p>
          </form>
        </div>
      </section>
    </main>;
}
