import { t, useLocale, getLocale } from "../i18n/language";
import { useEffect, useMemo, useState } from "react";
import { FaRobot, FaSearch, FaShieldAlt, FaUser, FaUserSecret, FaUserTie, FaUsers } from "react-icons/fa";
import api from "../api/axios";
import { useAuth } from "../context/auth-context";
import "./UserManagement.css";
const avatarIcons = {
  shield: FaShieldAlt,
  user: FaUser,
  secret: FaUserSecret,
  robot: FaRobot,
  analyst: FaUserTie
};
function formatDate(value) {
  if (!value) return "Not available";
  return new Date(value).toLocaleString(getLocale());
}
function getAvatarUrl(value) {
  if (!value) return null;
  if (value.startsWith("http")) {
    return value;
  }
  return value;
}
export default function UserManagement() {
  useLocale();
  const {
    user: currentUser
  } = useAuth();
  const [users, setUsers] = useState([]);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [updatingId, setUpdatingId] = useState(null);
  const [message, setMessage] = useState(null);
  const loadUsers = async () => {
    setLoading(true);
    setMessage(null);
    try {
      const response = await api.get("/users");
      setUsers(response.data);
    } catch (error) {
      setMessage({
        type: "error",
        text: error.response?.data?.error || "Unable to load users."
      });
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    let active = true;
    async function initialize() {
      try {
        const response = await api.get("/users");
        if (active) setUsers(response.data);
      } catch (requestError) {
        if (active) {
          setMessage({
            type: "error",
            text: requestError.response?.data?.error || "Unable to load users."
          });
        }
      } finally {
        if (active) setLoading(false);
      }
    }
    initialize();
    return () => {
      active = false;
    };
  }, []);
  const filteredUsers = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) {
      return users;
    }
    return users.filter(item => item.username.toLowerCase().includes(query) || item.email.toLowerCase().includes(query) || item.role.toLowerCase().includes(query));
  }, [search, users]);
  const statistics = useMemo(() => ({
    total: users.length,
    active: users.filter(item => item.is_active).length,
    admins: users.filter(item => item.role === "admin").length,
    disabled: users.filter(item => !item.is_active).length
  }), [users]);
  const updateAccess = async (target, changes) => {
    setUpdatingId(target.id);
    setMessage(null);
    try {
      const response = await api.put(`/users/${target.id}`, {
        role: changes.role ?? target.role,
        is_active: changes.is_active ?? target.is_active
      });
      setUsers(current => current.map(item => item.id === target.id ? response.data.user : item));
      setMessage({
        type: "success",
        text: response.data.message
      });
    } catch (error) {
      setMessage({
        type: "error",
        text: error.response?.data?.error || "Unable to update user access."
      });
    } finally {
      setUpdatingId(null);
    }
  };
  if (currentUser?.role !== "admin") {
    return <div className="usersAccessDenied">{t("Administrator access is required.")}</div>;
  }
  return <main className="usersPage">
      <header className="usersHeader">
        <div>
          <span>{t("ADMINISTRATION")}</span>
          <h1>{t("User Management")}</h1>
          <p>{t("Manage accounts, roles, and access to the SentinelX workspace.")}</p>
        </div>

        <div className="usersHeaderIcon">
          <FaUsers />
        </div>
      </header>

      <section className="usersStats">
        <Stat label={t("Total Users")} value={statistics.total} color="#38bdf8" />

        <Stat label={t("Active")} value={statistics.active} color="#22c55e" />

        <Stat label={t("Administrators")} value={statistics.admins} color="#8b5cf6" />

        <Stat label={t("Disabled")} value={statistics.disabled} color="#ef4444" />
      </section>

      <section className="usersToolbar">
        <label className="usersSearch">
          <FaSearch />

          <input value={search} onChange={event => setSearch(event.target.value)} placeholder={t("Search by username, email, or role")} />
        </label>

        <button type="button" onClick={loadUsers} disabled={loading}>
          {loading ? t("Refreshing...") : t("Refresh")}
        </button>
      </section>

      {t(message) && <div className={`usersMessage ${message.type}`}>
          {t(message.text)}
        </div>}

      <section className="usersTablePanel">
        {loading ? <div className="usersState">
            <span className="usersSpinner" />{t("Loading users...")}</div> : filteredUsers.length === 0 ? <div className="usersState">{t("No matching users were found.")}</div> : <div className="usersTableWrapper">
            <table className="usersTable">
              <thead>
                <tr>
                  <th>{t("User")}</th>
                  <th>{t("Role")}</th>
                  <th>{t("Status")}</th>
                  <th>{t("Created")}</th>
                  <th>{t("Access")}</th>
                </tr>
              </thead>

              <tbody>
                {filteredUsers.map(item => <UserRow key={item.id} item={item} isCurrentUser={item.id === currentUser.id} busy={updatingId === item.id} onUpdate={updateAccess} />)}
              </tbody>
            </table>
          </div>}
      </section>
    </main>;
}
function Stat({
  label,
  value,
  color
}) {
  useLocale();
  return <article style={{
    "--stat-color": color
  }}>
      <span>{t(label)}</span>
      <strong>{t(value)}</strong>
    </article>;
}
function UserRow({
  item,
  isCurrentUser,
  busy,
  onUpdate
}) {
  useLocale();
  const Icon = avatarIcons[item.avatar_icon] || FaShieldAlt;
  const avatarUrl = getAvatarUrl(item.avatar_url);
  const changeRole = event => {
    onUpdate(item, {
      role: event.target.value
    });
  };
  const changeAccountStatus = () => {
    const action = item.is_active ? "disable" : "enable";
    const confirmed = window.confirm(`${action} ${item.username}'s account?`);
    if (confirmed) {
      onUpdate(item, {
        is_active: !item.is_active
      });
    }
  };
  return <tr className={!item.is_active ? "isDisabled" : ""}>
      <td>
        <div className="userIdentity">
          <span className="userAvatar" style={{
          "--avatar-color": item.avatar_color || "#38bdf8"
        }}>
            {avatarUrl ? <img src={avatarUrl} alt="" /> : <Icon />}
          </span>

          <span>
            <strong>
              {item.username}

              {isCurrentUser && <em>{t("You")}</em>}
            </strong>

            <small>{item.email}</small>
          </span>
        </div>
      </td>

      <td>
        <select value={item.role} disabled={busy || isCurrentUser} onChange={changeRole} aria-label={t("Role for {0}", [item.username])}>
          <option value="analyst">{t("Analyst")}</option>
          <option value="admin">{t("Administrator")}</option>
        </select>
      </td>

      <td>
        <span className={`userStatus ${item.is_active ? "active" : "disabled"}`}>
          <i />

          {item.is_active ? t("Active") : t("Disabled")}
        </span>
      </td>

      <td className="userCreated">
        {formatDate(item.created_at)}
      </td>

      <td>
        <button type="button" className={`userAccessButton ${item.is_active ? "disable" : "enable"}`} disabled={busy || isCurrentUser} onClick={changeAccountStatus}>
          {busy ? t("Updating...") : item.is_active ? t("Disable") : t("Enable")}
        </button>
      </td>
    </tr>;
}
