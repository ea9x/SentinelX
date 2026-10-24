import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import './pages/index.css';
import App from './App.jsx';
import './i18n/i18n.css';
createRoot(document.getElementById('root')).render(<StrictMode>
    <App />
  </StrictMode>);
