import { useLocale, setLanguage, t } from '../i18n/language';
import { useLocation } from 'react-router-dom';

export default function LanguageSwitcher({ floating = false }) {
    const language = useLocale();
    const { pathname } = useLocation();
    if (floating && !['/login', '/register', '/forgot-password'].includes(pathname)) return null;
    return <label className={`language-switcher ${floating ? 'language-switcher--floating' : ''}`}>
        <span>{t('Language')}</span>
        <select aria-label={t('Interface language')} value={language} onChange={(event) => setLanguage(event.target.value)}>
            <option value="en" lang="en">English</option><option value="ar" lang="ar">العربية</option>
        </select>
    </label>;
}
