import { t, useLocale } from "../i18n/language";
import { useState } from "react";
import { FaEnvelope, FaShieldAlt } from "react-icons/fa";
import "./PrivacyBadge.css";
export default function PrivacyBadge() {
  useLocale();
  const [isOpen, setIsOpen] = useState(false);
  const contactEmail = import.meta.env.VITE_CONTACT_EMAIL || "Abdulsalammohammadsalah@gmail.com";
  return <div className="privacyBadge">
      <button type="button" className="privacyBadge__summary" onClick={() => setIsOpen(current => !current)} aria-expanded={isOpen} aria-controls="sentinelx-privacy-panel">
        <span className="privacyBadge__label">
          <strong>{t("Private Workspace")}</strong>
          <small>{t("Authorized access only")}</small>
        </span>
      </button>

      {isOpen && <div className="privacyBadge__panel" id="sentinelx-privacy-panel">
          <div className="privacyBadge__heading">
            <FaShieldAlt />
            <span>
              <strong>{t("SentinelX Privacy Notice")}</strong>
              <small>{t("Security Assessment Environment")}</small>
            </span>
          </div>

          <p>{t("This workspace is intended for authorized security testing and educational use. Scan results are stored in this SentinelX instance.")}</p>

          <a href={`mailto:${contactEmail}`} className="privacyBadge__email">
            <FaEnvelope />
            <span>{contactEmail}</span>
          </a>
        </div>}
    </div>;
}
