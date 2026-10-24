import { t, useLocale } from "../i18n/language";
import { useState } from "react";
import { FaRobot, FaShieldAlt, FaUser, FaUserSecret, FaUserTie } from "react-icons/fa";
import api from "../api/axios";
import { useAuth } from "../context/auth-context";
import "./Profile.css";
import LanguageSwitcher from '../components/LanguageSwitcher';
const avatarOptions = [{
  value: "shield",
  label: "Shield",
  icon: FaShieldAlt
}, {
  value: "user",
  label: "User",
  icon: FaUser
}, {
  value: "secret",
  label: "Security",
  icon: FaUserSecret
}, {
  value: "robot",
  label: "Automation",
  icon: FaRobot
}, {
  value: "analyst",
  label: "Analyst",
  icon: FaUserTie
}];
const colorOptions = ["#38bdf8", "#3b82f6", "#8b5cf6", "#22c55e", "#f59e0b", "#ef4444"];
export default function Profile() {
  useLocale();
  const {
    user
  } = useAuth();
  return <ProfileForm key={user?.id} />;
}
function ProfileForm() {
  useLocale();
  const {
    user,
    updateStoredUser
  } = useAuth();
  const [profile, setProfile] = useState(() => ({
    username: user?.username || "",
    email: user?.email || "",
    avatar_icon: user?.avatar_icon || "shield",
    avatar_color: user?.avatar_color || "#38bdf8",
    current_password: ""
  }));
  const [passwords, setPasswords] = useState({
    current_password: "",
    new_password: "",
    confirm_password: ""
  });
  const [profileMessage, setProfileMessage] = useState(null);
  const [passwordMessage, setPasswordMessage] = useState(null);
  const [savingProfile, setSavingProfile] = useState(false);
  const [savingPassword, setSavingPassword] = useState(false);
  const SelectedIcon = avatarOptions.find(option => option.value === profile.avatar_icon)?.icon || FaShieldAlt;
  const saveProfile = async event => {
    event.preventDefault();
    setSavingProfile(true);
    setProfileMessage(null);
    try {
      const response = await api.put("/auth/profile", profile);
      updateStoredUser(response.data.user);
      setProfile(current => ({
        ...current,
        current_password: ""
      }));
      setProfileMessage({
        type: "success",
        text: response.data.message
      });
    } catch (error) {
      setProfileMessage({
        type: "error",
        text: error.response?.data?.error || "Unable to update the profile."
      });
    } finally {
      setSavingProfile(false);
    }
  };
  const savePassword = async event => {
    event.preventDefault();
    setPasswordMessage(null);
    if (passwords.new_password !== passwords.confirm_password) {
      setPasswordMessage({
        type: "error",
        text: "New passwords do not match."
      });
      return;
    }
    setSavingPassword(true);
    try {
      const response = await api.put("/auth/password", {
        current_password: passwords.current_password,
        new_password: passwords.new_password
      });
      setPasswords({
        current_password: "",
        new_password: "",
        confirm_password: ""
      });
      setPasswordMessage({
        type: "success",
        text: response.data.message
      });
    } catch (error) {
      setPasswordMessage({
        type: "error",
        text: error.response?.data?.error || "Unable to change the password."
      });
    } finally {
      setSavingPassword(false);
    }
  };
  return <section className="profilePage">
      <header className="profileHeader">
        <div>
          <span>{t("ACCOUNT SETTINGS")}</span>
          <h1>{t("My Profile")}</h1>
          <p>{t("Manage your identity, appearance, email address, and password.")}</p>
        </div>
        <div className="profilePreview" style={{
        "--avatar-color": profile.avatar_color
      }}>
          <SelectedIcon />
          <strong>{profile.username || t("User")}</strong>
          <small>{profile.email}</small>
        </div>
      </header>

      <div className="profilePanel" style={{
      marginBottom: 20
    }}><LanguageSwitcher /></div>
      <div className="profileGrid">
        <form className="profilePanel" onSubmit={saveProfile}>
          <div className="profilePanelTitle">
            <h2>{t("Account Details")}</h2>
            <p>{t("Changing the username or email requires your current password.")}</p>
          </div>

          {profileMessage && <div className={`profileMessage ${profileMessage.type}`}>{t(profileMessage.text)}</div>}

          <label>
            <span>{t("Username")}</span>
            <input value={profile.username} onChange={event => setProfile({
            ...profile,
            username: event.target.value
          })} required />
          </label>
          <label>
            <span>{t("Email address")}</span>
            <input type="email" value={profile.email} onChange={event => setProfile({
            ...profile,
            email: event.target.value
          })} required />
          </label>

          <div className="profileFieldLabel">{t("Profile icon")}</div>
          <div className="avatarChoices">
            {avatarOptions.map(option => {
            const Icon = option.icon;
            return <button key={option.value} type="button" title={t(option.label)} className={profile.avatar_icon === option.value ? "selected" : ""} onClick={() => setProfile({
              ...profile,
              avatar_icon: option.value
            })}>
                  <Icon />
                </button>;
          })}
          </div>

          <div className="profileFieldLabel">{t("Icon color")}</div>
          <div className="colorChoices">
            {colorOptions.map(color => <button key={color} type="button" aria-label={t("Use {0}", [color])} className={profile.avatar_color === color ? "selected" : ""} style={{
            backgroundColor: color
          }} onClick={() => setProfile({
            ...profile,
            avatar_color: color
          })} />)}
          </div>

          <label>
            <span>{t("Current password")}</span>
            <input type="password" autoComplete="current-password" value={profile.current_password} onChange={event => setProfile({
            ...profile,
            current_password: event.target.value
          })} placeholder={t("Required when changing account details")} />
          </label>

          <button className="profileSubmit" type="submit" disabled={savingProfile}>
            {savingProfile ? t("Saving...") : t("Save Profile")}
          </button>
        </form>

        <form className="profilePanel" onSubmit={savePassword}>
          <div className="profilePanelTitle">
            <h2>{t("Change Password")}</h2>
            <p>{t("Use at least eight characters and avoid reusing your current password.")}</p>
          </div>

          {passwordMessage && <div className={`profileMessage ${passwordMessage.type}`}>{t(passwordMessage.text)}</div>}

          <label>
            <span>{t("Current password")}</span>
            <input type="password" autoComplete="current-password" value={passwords.current_password} onChange={event => setPasswords({
            ...passwords,
            current_password: event.target.value
          })} required />
          </label>
          <label>
            <span>{t("New password")}</span>
            <input type="password" autoComplete="new-password" minLength="8" value={passwords.new_password} onChange={event => setPasswords({
            ...passwords,
            new_password: event.target.value
          })} required />
          </label>
          <label>
            <span>{t("Confirm new password")}</span>
            <input type="password" autoComplete="new-password" minLength="8" value={passwords.confirm_password} onChange={event => setPasswords({
            ...passwords,
            confirm_password: event.target.value
          })} required />
          </label>

          <button className="profileSubmit" type="submit" disabled={savingPassword}>
            {savingPassword ? t("Updating...") : t("Change Password")}
          </button>
        </form>
      </div>

    </section>;
}
