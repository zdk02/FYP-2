import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Settings as SettingsIcon, User, Bell, Shield, Key,
  Save, Loader2, Eye, EyeOff, CheckCircle, AlertCircle,
  Moon, Sun, Globe, Database, Zap
} from 'lucide-react'
import { useAuthStore } from '../stores/authStore'
import { usersApi, settingsApi } from '../services/api'
import toast from 'react-hot-toast'

const PREFS_STORAGE_KEY = 'minerva_user_prefs'
const NOTIF_STORAGE_KEY = 'minerva_user_notifications'

const defaultPrefs = {
  timezone: 'UTC',
  date_format: 'YYYY-MM-DD',
  default_report_format: 'pdf',
}

const defaultNotifs = {
  email_on_scan_complete: true,
  email_on_campaign_complete: true,
  email_on_critical_finding: true,
  in_app_notifications: true,
}

function loadJSON(key, fallback) {
  try {
    const raw = localStorage.getItem(key)
    if (!raw) return fallback
    return { ...fallback, ...JSON.parse(raw) }
  } catch {
    return fallback
  }
}

export default function Settings() {
  const queryClient = useQueryClient()
  const { user, logout } = useAuthStore()
  const [activeTab, setActiveTab] = useState('profile')
  const [showCurrentPassword, setShowCurrentPassword] = useState(false)
  const [showNewPassword, setShowNewPassword] = useState(false)
  
  const [profile, setProfile] = useState({
    name: user?.name || '',
    email: user?.email || '',
  })
  
  const [password, setPassword] = useState({
    current_password: '',
    new_password: '',
    confirm_password: '',
  })
  
  const [notifications, setNotifications] = useState(() => loadJSON(NOTIF_STORAGE_KEY, defaultNotifs))
  const [prefs, setPrefs] = useState(() => loadJSON(PREFS_STORAGE_KEY, defaultPrefs))
  const [savingNotifs, setSavingNotifs] = useState(false)
  const [savingPrefs, setSavingPrefs] = useState(false)

  const { data: settings, isLoading: settingsLoading } = useQuery({
    queryKey: ['settings'],
    queryFn: settingsApi.getAll,
  })

  const updateProfileMutation = useMutation({
    mutationFn: (data) => usersApi.update(user.id, data),
    onSuccess: () => {
      toast.success('Profile updated successfully')
      queryClient.invalidateQueries({ queryKey: ['user'] })
    },
    onError: (error) => toast.error(error.response?.data?.message || 'Failed to update profile')
  })

  const changePasswordMutation = useMutation({
    mutationFn: (data) => usersApi.changePassword(user.id, data),
    onSuccess: () => {
      toast.success('Password changed successfully')
      setPassword({ current_password: '', new_password: '', confirm_password: '' })
    },
    onError: (error) => toast.error(error.response?.data?.message || 'Failed to change password')
  })

  const handleProfileSubmit = (e) => {
    e.preventDefault()
    updateProfileMutation.mutate(profile)
  }

  const handlePasswordSubmit = (e) => {
    e.preventDefault()
    if (password.new_password !== password.confirm_password) {
      toast.error('Passwords do not match')
      return
    }
    if (password.new_password.length < 8) {
      toast.error('Password must be at least 8 characters')
      return
    }
    changePasswordMutation.mutate({
      current_password: password.current_password,
      new_password: password.new_password,
    })
  }

  const saveNotifications = async () => {
    setSavingNotifs(true)
    try {
      localStorage.setItem(NOTIF_STORAGE_KEY, JSON.stringify(notifications))
      toast.success('Notification preferences saved')
    } catch (err) {
      toast.error('Could not save preferences locally')
    } finally {
      setSavingNotifs(false)
    }
  }

  const savePreferences = async () => {
    setSavingPrefs(true)
    try {
      localStorage.setItem(PREFS_STORAGE_KEY, JSON.stringify(prefs))
      toast.success('Preferences saved')
    } catch (err) {
      toast.error('Could not save preferences locally')
    } finally {
      setSavingPrefs(false)
    }
  }

  const tabs = [
    { id: 'profile', name: 'Profile', icon: User },
    { id: 'security', name: 'Security', icon: Shield },
    { id: 'notifications', name: 'Notifications', icon: Bell },
    { id: 'preferences', name: 'Preferences', icon: Zap },
  ]

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-3">
          <SettingsIcon className="w-8 h-8 text-aegis-blue" />
          Settings
        </h1>
        <p className="text-gray-400 mt-1">Manage your account and preferences</p>
      </div>

      <div className="flex gap-6">
        {/* Sidebar Tabs */}
        <div className="w-56 shrink-0">
          <nav className="space-y-1">
            {tabs.map((tab) => {
              const Icon = tab.icon
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-colors ${
                    activeTab === tab.id
                      ? 'bg-aegis-blue/10 text-aegis-blue'
                      : 'text-gray-400 hover:text-white hover:bg-dark-800'
                  }`}
                >
                  <Icon className="w-5 h-5" />
                  {tab.name}
                </button>
              )
            })}
          </nav>
        </div>

        {/* Content */}
        <div className="flex-1">
          {/* Profile Tab */}
          {activeTab === 'profile' && (
            <div className="card p-6">
              <h2 className="text-lg font-semibold text-white mb-6">Profile Information</h2>
              
              <form onSubmit={handleProfileSubmit} className="space-y-6 max-w-md">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Full Name</label>
                  <input
                    type="text"
                    value={profile.name}
                    onChange={(e) => setProfile({ ...profile, name: e.target.value })}
                    className="input w-full"
                    placeholder="Your name"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Email Address</label>
                  <input
                    type="email"
                    value={profile.email}
                    onChange={(e) => setProfile({ ...profile, email: e.target.value })}
                    className="input w-full"
                    placeholder="you@example.com"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Role</label>
                  <div className="flex items-center gap-2 px-4 py-3 bg-dark-800 rounded-lg">
                    <Shield className="w-4 h-4 text-aegis-blue" />
                    <span className="text-white capitalize">{user?.role || 'User'}</span>
                  </div>
                  <p className="text-xs text-gray-500 mt-1">Contact an administrator to change your role</p>
                </div>

                <button
                  type="submit"
                  disabled={updateProfileMutation.isPending}
                  className="btn-primary flex items-center gap-2"
                >
                  {updateProfileMutation.isPending ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Saving...
                    </>
                  ) : (
                    <>
                      <Save className="w-4 h-4" />
                      Save Changes
                    </>
                  )}
                </button>
              </form>
            </div>
          )}

          {/* Security Tab */}
          {activeTab === 'security' && (
            <div className="space-y-6">
              {/* Change Password */}
              <div className="card p-6">
                <h2 className="text-lg font-semibold text-white mb-6">Change Password</h2>
                
                <form onSubmit={handlePasswordSubmit} className="space-y-6 max-w-md">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Current Password</label>
                    <div className="relative">
                      <input
                        type={showCurrentPassword ? 'text' : 'password'}
                        value={password.current_password}
                        onChange={(e) => setPassword({ ...password, current_password: e.target.value })}
                        className="input w-full pr-10"
                        placeholder="Enter current password"
                        required
                      />
                      <button
                        type="button"
                        onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
                      >
                        {showCurrentPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">New Password</label>
                    <div className="relative">
                      <input
                        type={showNewPassword ? 'text' : 'password'}
                        value={password.new_password}
                        onChange={(e) => setPassword({ ...password, new_password: e.target.value })}
                        className="input w-full pr-10"
                        placeholder="Enter new password"
                        required
                      />
                      <button
                        type="button"
                        onClick={() => setShowNewPassword(!showNewPassword)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
                      >
                        {showNewPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                    <p className="text-xs text-gray-500 mt-1">Minimum 8 characters</p>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Confirm New Password</label>
                    <input
                      type="password"
                      value={password.confirm_password}
                      onChange={(e) => setPassword({ ...password, confirm_password: e.target.value })}
                      className="input w-full"
                      placeholder="Confirm new password"
                      required
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={changePasswordMutation.isPending}
                    className="btn-primary flex items-center gap-2"
                  >
                    {changePasswordMutation.isPending ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin" />
                        Changing...
                      </>
                    ) : (
                      <>
                        <Key className="w-4 h-4" />
                        Change Password
                      </>
                    )}
                  </button>
                </form>
              </div>

              {/* Session Info */}
              <div className="card p-6">
                <h2 className="text-lg font-semibold text-white mb-4">Session</h2>
                <div className="flex items-center justify-between p-4 bg-dark-800 rounded-lg">
                  <div className="flex items-center gap-3">
                    <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                    <div>
                      <div className="text-white">Current Session</div>
                      <div className="text-sm text-gray-400">Active now</div>
                    </div>
                  </div>
                  <button 
                    onClick={logout}
                    className="btn-secondary text-red-400 border-red-400/20 hover:bg-red-400/10"
                  >
                    Sign Out
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Notifications Tab */}
          {activeTab === 'notifications' && (
            <div className="card p-6">
              <h2 className="text-lg font-semibold text-white mb-6">Notification Preferences</h2>
              
              <div className="space-y-4 max-w-md">
                <label className="flex items-center justify-between p-4 bg-dark-800 rounded-lg cursor-pointer">
                  <div>
                    <div className="text-white">Scan Complete Notifications</div>
                    <div className="text-sm text-gray-400">Receive email when scans finish</div>
                  </div>
                  <input
                    type="checkbox"
                    checked={notifications.email_on_scan_complete}
                    onChange={(e) => setNotifications({ ...notifications, email_on_scan_complete: e.target.checked })}
                    className="w-5 h-5 rounded bg-dark-700 border-dark-600 text-aegis-blue focus:ring-aegis-blue"
                  />
                </label>

                <label className="flex items-center justify-between p-4 bg-dark-800 rounded-lg cursor-pointer">
                  <div>
                    <div className="text-white">Campaign Complete Notifications</div>
                    <div className="text-sm text-gray-400">Receive email when campaigns finish</div>
                  </div>
                  <input
                    type="checkbox"
                    checked={notifications.email_on_campaign_complete}
                    onChange={(e) => setNotifications({ ...notifications, email_on_campaign_complete: e.target.checked })}
                    className="w-5 h-5 rounded bg-dark-700 border-dark-600 text-aegis-blue focus:ring-aegis-blue"
                  />
                </label>

                <label className="flex items-center justify-between p-4 bg-dark-800 rounded-lg cursor-pointer">
                  <div>
                    <div className="text-white">Critical Finding Alerts</div>
                    <div className="text-sm text-gray-400">Immediate notification for critical vulnerabilities</div>
                  </div>
                  <input
                    type="checkbox"
                    checked={notifications.email_on_critical_finding}
                    onChange={(e) => setNotifications({ ...notifications, email_on_critical_finding: e.target.checked })}
                    className="w-5 h-5 rounded bg-dark-700 border-dark-600 text-aegis-blue focus:ring-aegis-blue"
                  />
                </label>

                <label className="flex items-center justify-between p-4 bg-dark-800 rounded-lg cursor-pointer">
                  <div>
                    <div className="text-white">In-App Notifications</div>
                    <div className="text-sm text-gray-400">Show notifications within the platform</div>
                  </div>
                  <input
                    type="checkbox"
                    checked={notifications.in_app_notifications}
                    onChange={(e) => setNotifications({ ...notifications, in_app_notifications: e.target.checked })}
                    className="w-5 h-5 rounded bg-dark-700 border-dark-600 text-aegis-blue focus:ring-aegis-blue"
                  />
                </label>

                <button
                  type="button"
                  onClick={saveNotifications}
                  disabled={savingNotifs}
                  className="btn-primary flex items-center gap-2 mt-6"
                >
                  {savingNotifs ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                  Save Preferences
                </button>
              </div>
            </div>
          )}

          {/* Preferences Tab */}
          {activeTab === 'preferences' && (
            <div className="card p-6">
              <h2 className="text-lg font-semibold text-white mb-6">Application Preferences</h2>
              
              <div className="space-y-6 max-w-md">
                {/* Theme */}
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-3">Theme</label>
                  <div className="grid grid-cols-2 gap-3">
                    <button className="flex items-center gap-3 p-4 bg-dark-800 rounded-lg border-2 border-aegis-blue">
                      <Moon className="w-5 h-5 text-aegis-blue" />
                      <span className="text-white">Dark</span>
                    </button>
                    <button className="flex items-center gap-3 p-4 bg-dark-800 rounded-lg border border-dark-600 opacity-50 cursor-not-allowed">
                      <Sun className="w-5 h-5 text-gray-400" />
                      <span className="text-gray-400">Light</span>
                    </button>
                  </div>
                  <p className="text-xs text-gray-500 mt-2">Light theme coming soon</p>
                </div>

                {/* Timezone */}
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Timezone</label>
                  <select
                    value={prefs.timezone}
                    onChange={(e) => setPrefs({ ...prefs, timezone: e.target.value })}
                    className="input w-full"
                  >
                    <option value="UTC">UTC (Coordinated Universal Time)</option>
                    <option value="America/New_York">Eastern Time (ET)</option>
                    <option value="America/Los_Angeles">Pacific Time (PT)</option>
                    <option value="Europe/London">London (GMT/BST)</option>
                    <option value="Europe/Paris">Central European Time (CET)</option>
                    <option value="Asia/Tokyo">Japan Standard Time (JST)</option>
                  </select>
                </div>

                {/* Date Format */}
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Date Format</label>
                  <select
                    value={prefs.date_format}
                    onChange={(e) => setPrefs({ ...prefs, date_format: e.target.value })}
                    className="input w-full"
                  >
                    <option value="MM/DD/YYYY">MM/DD/YYYY</option>
                    <option value="DD/MM/YYYY">DD/MM/YYYY</option>
                    <option value="YYYY-MM-DD">YYYY-MM-DD</option>
                  </select>
                </div>

                {/* Default Report Format */}
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Default Report Format</label>
                  <select
                    value={prefs.default_report_format}
                    onChange={(e) => setPrefs({ ...prefs, default_report_format: e.target.value })}
                    className="input w-full"
                  >
                    <option value="pdf">PDF</option>
                    <option value="html">HTML</option>
                    <option value="json">JSON</option>
                    <option value="sarif">SARIF</option>
                  </select>
                </div>

                <button
                  type="button"
                  onClick={savePreferences}
                  disabled={savingPrefs}
                  className="btn-primary flex items-center gap-2 mt-6"
                >
                  {savingPrefs ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                  Save Preferences
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
