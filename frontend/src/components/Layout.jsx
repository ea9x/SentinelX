import { useLocale } from "../i18n/language";
import Sidebar from "./Sidebar";
import "./Layout.css";
export default function Layout({
  children
}) {
  useLocale();
  return <div className="sentinel-layout">
      <div className="sentinel-orb sentinel-orb-one" aria-hidden="true" />
      <div className="sentinel-orb sentinel-orb-two" aria-hidden="true" />
      <div className="sentinel-scan-line" aria-hidden="true" />

      <div className="sentinel-background-word" aria-hidden="true">
        SentinelX
      </div>

      <div className="sentinel-particles" aria-hidden="true">
        {Array.from({
        length: 6
      }, (_, index) => <span className="sentinel-particle" key={index} />)}
      </div>

      <Sidebar />
      <main className="sentinel-content">{children}</main>
    </div>;
}
