import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import Marketing from './Marketing';
import SetupWizard from './SetupWizard';
import './styles.css';
import './agent-styles.css';
import './image-styles.css';
import './activity-styles.css';

const path = window.location.pathname;
const view = path === '/' ? <Marketing /> :
  path === '/app' || path === '/app/' || path === '/app/setup' ? <SetupWizard /> :
  path === '/app/workspace' || path === '/app/workspace/' ? <App /> :
  <main style={{ padding: 48, fontFamily: 'system-ui' }}>
    <h1>Page not found</h1>
    <p><a href="/">Return to BootNexa</a> or <a href="/app">open the guided app</a>.</p>
  </main>;

createRoot(document.getElementById('root')!).render(<React.StrictMode>{view}</React.StrictMode>);
