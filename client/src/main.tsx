import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import { AuthProvider } from './context/AuthContext'
import { ToastHost } from './components/ui'
import './index.css'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <ToastHost>
        <AuthProvider>
          <App />
        </AuthProvider>
      </ToastHost>
    </BrowserRouter>
  </StrictMode>,
)
