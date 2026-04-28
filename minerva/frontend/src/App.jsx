import { useEffect } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuthStore } from './stores/authStore'

// Layout
import MainLayout from './components/layout/MainLayout'
import AuthLayout from './components/layout/AuthLayout'

// Pages
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Attacks from './pages/Attacks'
import AttackDetail from './pages/AttackDetail'
import Targets from './pages/Targets'
import Campaigns from './pages/Campaigns'
import CampaignDetail from './pages/CampaignDetail'
import CampaignBuilder from './pages/CampaignBuilder'
import Reports from './pages/Reports'
import ReportDetail from './pages/ReportDetail'
import Scans from './pages/Scans'
import Scanners from './pages/Scanners'
import ScannerDetail from './pages/ScannerDetail'
import Settings from './pages/Settings'
import AdminUsers from './pages/admin/AdminUsers'
import AdminCategories from './pages/admin/AdminCategories'
import AdminAttacks from './pages/admin/AdminAttacks'
import AdminPayloads from './pages/admin/AdminPayloads'
import AdminTechniques from './pages/admin/AdminTechniques'
import AdminConnections from './pages/admin/AdminConnections'
import AdminScanners from './pages/admin/AdminScanners'

// Protected Route Component
function ProtectedRoute({ children, requiredRoles = [] }) {
  const { isAuthenticated, user } = useAuthStore()
  
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }
  
  if (requiredRoles.length > 0 && !requiredRoles.includes(user?.role)) {
    return <Navigate to="/dashboard" replace />
  }
  
  return children
}

// Admin Route Component
function AdminRoute({ children }) {
  return (
    <ProtectedRoute requiredRoles={['admin']}>
      {children}
    </ProtectedRoute>
  )
}

function App() {
  const checkAuth = useAuthStore((s) => s.checkAuth)
  useEffect(() => {
    checkAuth()
  }, [checkAuth])

  return (
    <Routes>
      {/* Auth Routes */}
      <Route element={<AuthLayout />}>
        <Route path="/login" element={<Login />} />
      </Route>

      {/* Protected Routes */}
      <Route element={
        <ProtectedRoute>
          <MainLayout />
        </ProtectedRoute>
      }>
        {/* Dashboard */}
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />

        {/* Attack Library */}
        <Route path="/attacks" element={<Attacks />} />
        <Route path="/attacks/:id" element={<AttackDetail />} />

        {/* Targets */}
        <Route path="/targets" element={<Targets />} />

        {/* Campaigns */}
        <Route path="/campaigns" element={<Campaigns />} />
        <Route path="/campaigns/new" element={<CampaignBuilder />} />
        <Route path="/campaigns/:id" element={<CampaignDetail />} />
        <Route path="/campaigns/:id/edit" element={<CampaignBuilder />} />

        {/* Reports */}
        <Route path="/reports" element={<Reports />} />
        <Route path="/reports/:id" element={<ReportDetail />} />

        {/* Scans */}
        <Route path="/scans" element={<Scans />} />

        {/* Scanners (YAML plugin-based) */}
        <Route path="/scanners" element={<Scanners />} />
        <Route path="/scanners/:pluginId" element={<ScannerDetail />} />

        {/* Settings */}
        <Route path="/settings" element={<Settings />} />

        {/* Admin Routes */}
        <Route path="/admin/users" element={<AdminRoute><AdminUsers /></AdminRoute>} />
        <Route path="/admin/categories" element={<AdminRoute><AdminCategories /></AdminRoute>} />
        <Route path="/admin/attacks" element={<AdminRoute><AdminAttacks /></AdminRoute>} />
        <Route path="/admin/payloads" element={<AdminRoute><AdminPayloads /></AdminRoute>} />
        <Route path="/admin/techniques" element={<AdminRoute><AdminTechniques /></AdminRoute>} />
        <Route path="/admin/connections" element={<AdminRoute><AdminConnections /></AdminRoute>} />
        <Route path="/admin/scanners" element={<AdminRoute><AdminScanners /></AdminRoute>} />
      </Route>

      {/* 404 */}
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  )
}

export default App
