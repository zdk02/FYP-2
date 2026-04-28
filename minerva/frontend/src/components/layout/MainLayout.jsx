import { useState } from 'react'
import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useAuthStore } from '../../stores/authStore'
import {
  LayoutDashboard,
  Crosshair,
  Target,
  Rocket,
  FileText,
  Radar,
  Settings,
  Users,
  FolderTree,
  Package,
  Fingerprint,
  Cable,
  ShieldCheck,
  Database,
  LogOut,
  ChevronDown,
  ChevronRight,
  Shield,
  Menu,
  X,
  Bell,
  Search,
} from 'lucide-react'

const navItems = [
  { name: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
  { name: 'Attack Library', path: '/attacks', icon: Crosshair },
  { name: 'Scanners', path: '/scanners', icon: ShieldCheck },
  { name: 'Targets', path: '/targets', icon: Target },
  { name: 'Campaigns', path: '/campaigns', icon: Rocket },
  { name: 'Reports', path: '/reports', icon: FileText },
  { name: 'Scans', path: '/scans', icon: Radar },
]

const adminItems = [
  { name: 'Users', path: '/admin/users', icon: Users },
  { name: 'Categories', path: '/admin/categories', icon: FolderTree },
  { name: 'Attacks', path: '/admin/attacks', icon: Crosshair },
  { name: 'Payloads', path: '/admin/payloads', icon: Package },
  { name: 'Techniques', path: '/admin/techniques', icon: Fingerprint },
  { name: 'Connections', path: '/admin/connections', icon: Cable },
  { name: 'CVE Database', path: '/admin/scanners', icon: Database },
]

function Sidebar({ isOpen, onClose }) {
  const { user, logout, isAdmin } = useAuthStore()
  const navigate = useNavigate()
  const [adminExpanded, setAdminExpanded] = useState(false)

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  return (
    <>
      {/* Overlay for mobile */}
      {isOpen && (
        <div 
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={onClose}
        />
      )}

      {/* Sidebar */}
      <aside className={`
        fixed top-0 left-0 z-50 h-full w-64 bg-dark-900 border-r border-dark-800
        transform transition-transform duration-300 ease-in-out
        lg:translate-x-0 lg:static
        ${isOpen ? 'translate-x-0' : '-translate-x-full'}
      `}>
        {/* Logo */}
        <div className="h-16 flex items-center justify-between px-4 border-b border-dark-800">
          <div className="flex items-center gap-3">
            <img src="/minervaIcon.png" alt="Minerva" className="w-10 h-10" />
            <div>
              <h1 className="text-lg font-bold text-white">Minerva</h1>
              <p className="text-[10px] text-dark-400 -mt-0.5">MCP Pentesting</p>
            </div>
          </div>
          <button onClick={onClose} className="lg:hidden text-dark-400 hover:text-white">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 py-4 px-3 space-y-1 overflow-y-auto h-[calc(100vh-180px)]">
          {navItems.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              onClick={onClose}
              className={({ isActive }) => `
                sidebar-link ${isActive ? 'active' : ''}
              `}
            >
              <item.icon className="w-5 h-5" />
              <span>{item.name}</span>
            </NavLink>
          ))}

          {/* Admin Section */}
          {isAdmin() && (
            <div className="pt-4 mt-4 border-t border-dark-800">
              <button
                onClick={() => setAdminExpanded(!adminExpanded)}
                className="sidebar-link w-full justify-between"
              >
                <span className="flex items-center gap-3">
                  <Settings className="w-5 h-5" />
                  <span>Admin</span>
                </span>
                {adminExpanded ? (
                  <ChevronDown className="w-4 h-4" />
                ) : (
                  <ChevronRight className="w-4 h-4" />
                )}
              </button>
              
              {adminExpanded && (
                <div className="ml-4 mt-1 space-y-1">
                  {adminItems.map((item) => (
                    <NavLink
                      key={item.path}
                      to={item.path}
                      onClick={onClose}
                      className={({ isActive }) => `
                        sidebar-link text-sm ${isActive ? 'active' : ''}
                      `}
                    >
                      <item.icon className="w-4 h-4" />
                      <span>{item.name}</span>
                    </NavLink>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Settings */}
          <NavLink
            to="/settings"
            onClick={onClose}
            className={({ isActive }) => `
              sidebar-link mt-4 ${isActive ? 'active' : ''}
            `}
          >
            <Settings className="w-5 h-5" />
            <span>Settings</span>
          </NavLink>
        </nav>

        {/* User Section */}
        <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-dark-800 bg-dark-900">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-full bg-dark-700 flex items-center justify-center">
              <span className="text-sm font-medium text-white">
                {user?.username?.charAt(0).toUpperCase() || 'U'}
              </span>
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-white truncate">{user?.username}</p>
              <p className="text-xs text-dark-400 capitalize">{user?.role}</p>
            </div>
            <button
              onClick={handleLogout}
              className="p-2 text-dark-400 hover:text-red-400 hover:bg-dark-800 rounded-lg transition-colors"
              title="Logout"
            >
              <LogOut className="w-5 h-5" />
            </button>
          </div>
        </div>
      </aside>
    </>
  )
}

function Header({ onMenuClick }) {
  return (
    <header className="h-16 bg-dark-900 border-b border-dark-800 px-4 flex items-center justify-between">
      <div className="flex items-center gap-4">
        <button
          onClick={onMenuClick}
          className="lg:hidden p-2 text-dark-400 hover:text-white hover:bg-dark-800 rounded-lg"
        >
          <Menu className="w-5 h-5" />
        </button>
        
        {/* Search */}
        <div className="hidden md:flex items-center gap-2 bg-dark-800 rounded-lg px-3 py-2 w-80">
          <Search className="w-4 h-4 text-dark-500" />
          <input
            type="text"
            placeholder="Search attacks, targets, campaigns..."
            className="bg-transparent border-none outline-none text-sm text-white placeholder-dark-500 w-full"
          />
          <kbd className="hidden lg:inline-flex text-[10px] text-dark-500 bg-dark-700 px-1.5 py-0.5 rounded">
            ⌘K
          </kbd>
        </div>
      </div>

      <div className="flex items-center gap-2">
        {/* Notifications */}
        <button className="p-2 text-dark-400 hover:text-white hover:bg-dark-800 rounded-lg relative">
          <Bell className="w-5 h-5" />
          <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-cyber-red rounded-full" />
        </button>
      </div>
    </header>
  )
}

export default function MainLayout() {
  const [sidebarOpen, setSidebarOpen] = useState(false)

  return (
    <div className="min-h-screen bg-dark-950 flex">
      <Sidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />
      
      <div className="flex-1 flex flex-col min-w-0">
        <Header onMenuClick={() => setSidebarOpen(true)} />
        
        <main className="flex-1 p-6 overflow-auto bg-grid">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
