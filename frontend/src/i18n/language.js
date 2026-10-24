import { useSyncExternalStore } from 'react';
import { ar } from './ar.js';

const key = 'sentinelx.language';
const listeners = new Set();
let language = 'en';
try { language = localStorage.getItem(key) === 'ar' ? 'ar' : 'en'; } catch { /* Storage may be unavailable. */ }
function applyDirection() {
    if (typeof document === 'undefined') return;
    document.documentElement.lang = language;
    document.documentElement.dir = language === 'ar' ? 'rtl' : 'ltr';
}
applyDirection();
export const getLanguage = () => language;
export const getLocale = () => language === 'ar' ? 'ar' : 'en-US';
export function setLanguage(next) {
    if (!['ar', 'en'].includes(next) || next === language) return;
    language = next;
    try { localStorage.setItem(key, next); } catch { /* Keep an in-memory preference. */ }
    applyDirection();
    listeners.forEach((listener) => listener());
}
function subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); }
export function useLocale() { return useSyncExternalStore(subscribe, getLanguage, () => 'en'); }
if (typeof window !== 'undefined') {
    window.addEventListener('storage', (event) => {
        if (event.key === key) setLanguage(event.newValue === 'ar' ? 'ar' : 'en');
    });
}
const reverse = new Map(Object.entries(ar).map(([english, arabic]) => [arabic, english]));
function pattern(template) {
    return new RegExp('^' + template.split(/(\{\d+\})/).map((part) => /^\{\d+\}$/.test(part) ? '(.+?)' : part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('') + '$');
}
const patterns = Object.entries(ar).filter(([key]) => /\{\d+\}/.test(key)).map(([english, arabic]) => ({ english, arabic, en:pattern(english) }));
export function t(value, values = []) {
    if (typeof value !== 'string') return value;
    const trimmed = value.trim();
    const source = reverse.get(trimmed) || trimmed;
    const translated = Object.hasOwn(ar,source) && typeof ar[source] === 'string' ? ar[source] : null;
    let result = language === 'ar' ? translated || source : source;
    if (language === 'ar' && !translated) {
        const running = /^Running (.+)$/.exec(source);
        if (running) result = 'جارٍ تشغيل ' + running[1];
    }
    let interpolated = false;
    if (!translated && !reverse.has(trimmed)) {
        for (const entry of patterns) {
            const found = entry.en.exec(trimmed);
            if (found && language === 'ar') { result=entry.arabic.replace(/\{(\d+)\}/g, (_, index) => found[Number(index)+1] ?? ''); interpolated = true; break; }
        }
    }
    if (!interpolated && values.length) result = result.replace(/\{(\d+)\}/g, (_, index) => String(values[index] ?? ''));
    return value.slice(0, value.length - value.trimStart().length) + result + value.slice(value.trimEnd().length);
}
