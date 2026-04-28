import { Outlet, Navigate } from 'react-router-dom'
import { useAuthStore } from '../../stores/authStore'
import { Shield } from 'lucide-react'

export default function AuthLayout() {
  const { isAuthenticated } = useAuthStore()

  // Redirect to dashboard if already authenticated
  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />
  }

  return (
    <div className="min-h-screen bg-dark-950 flex items-center justify-center p-4 bg-grid relative overflow-hidden">
      {/* Background Effects */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute -top-1/2 -left-1/2 w-full h-full bg-gradient-radial from-aegis-600/10 to-transparent rounded-full blur-3xl" />
        <div className="absolute -bottom-1/2 -right-1/2 w-full h-full bg-gradient-radial from-cyan-600/10 to-transparent rounded-full blur-3xl" />
      </div>

      {/* Login Card */}
      <div className="w-full max-w-md relative z-10">
        {/* Logo */}
        <div className="text-center mb-8">
          <img src="/minervaIcon.png" alt="Minerva" className="w-16 h-16 mx-auto mb-4" />
          <h1 className="text-3xl font-bold text-white mb-1">Minerva</h1>
          <p className="text-dark-400">MCP Pentesting Framework</p>
        </div>

        {/* Form Container */}
        <div className="card">
          <Outlet />
        </div>

        {/* Footer */}
        <p className="text-center text-dark-500 text-sm mt-6">
          MCP / Agentic AI Security Testing Framework
        </p>
      </div>
    </div>
  )
}
