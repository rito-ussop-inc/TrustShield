import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Dashboard } from './pages/Dashboard';
import { ResultPage } from './pages/ResultPage';
import './index.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <div className="min-h-screen">
        <nav className="bg-shield-900 text-white px-4 py-3 flex items-center justify-between">
          <span className="font-bold">🛡️ TRUSTSHIELD</span>
          <span className="text-xs opacity-80">Verify Before You Trust</span>
        </nav>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/analysis/:id" element={<ResultPage />} />
        </Routes>
      </div>
    </BrowserRouter>
  </React.StrictMode>
);
