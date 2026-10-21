import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import './styles.css';
import './agent-styles.css';
import './image-styles.css';

createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>);
