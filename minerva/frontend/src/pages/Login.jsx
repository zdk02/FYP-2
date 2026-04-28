import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '../stores/authStore'
import { Eye, EyeOff, LogIn, AlertCircle } from 'lucide-react'

export default function Login() {
  const navigate = useNavigate()
  const { login, isLoading, error } = useAuthStore()
  
  const [formData, setFormData] = useState({
    email: '',
    password: '',
  })
  const [showPassword, setShowPassword] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    const result = await login(formData.email, formData.password)
    if (result.success) {
      navigate('/dashboard')
    }
  }

  return (
    <div className="card-body">
      <h2 className="text-xl font-semibold text-white mb-6">Sign in to your account</h2>
      
      {error && (
        <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg flex items-center gap-2 text-red-400 text-sm">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="label">Email Address</label>
          <input
            type="email"
            className="input"
            placeholder="admin@aegis.local"
            value={formData.email}
            onChange={(e) => setFormData({ ...formData, email: e.target.value })}
            required
            autoFocus
          />
        </div>

        <div>
          <label className="label">Password</label>
          <div className="relative">
            <input
              type={showPassword ? 'text' : 'password'}
              className="input pr-10"
              placeholder="••••••••"
              value={formData.password}
              onChange={(e) => setFormData({ ...formData, password: e.target.value })}
              required
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-dark-500 hover:text-dark-300"
            >
              {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
        </div>

        <button
          type="submit"
          disabled={isLoading}
          className="btn-primary w-full"
        >
          {isLoading ? (
            <div className="spinner w-5 h-5" />
          ) : (
            <>
              <LogIn className="w-4 h-4" />
              Sign In
            </>
          )}
        </button>
      </form>

      <div className="mt-6 pt-6 border-t border-dark-800">
        <p className="text-xs text-dark-500 text-center">
          Default credentials: <code className="text-dark-400">admin@aegis.local</code> / <code className="text-dark-400">admin123</code>
        </p>
      </div>
    </div>
  )
}
