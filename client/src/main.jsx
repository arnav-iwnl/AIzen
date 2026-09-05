import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { Toaster } from 'sonner'
import './index.css'
import App from './App.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
    <Toaster
      theme="dark"
      position="top-right"
      richColors
      closeButton
      toastOptions={{ className: 'font-mono text-sm' }}
    />
  </StrictMode>,
)
