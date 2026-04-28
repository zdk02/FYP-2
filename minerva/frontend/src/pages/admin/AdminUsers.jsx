import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { 
  Users, Plus, Edit2, Trash2, Shield, Search,
  Loader2, CheckCircle, XCircle, UserPlus, Key,
  Mail, Calendar, MoreVertical
} from 'lucide-react'
import { usersApi } from '../../services/api'
import toast from 'react-hot-toast'
import { format } from 'date-fns'

const roleColors = {
  admin: 'bg-red-500/20 text-red-400',
  manager: 'bg-purple-500/20 text-purple-400',
  operator: 'bg-blue-500/20 text-blue-400',
  viewer: 'bg-gray-500/20 text-gray-400',
}

const roles = ['admin', 'manager', 'operator', 'viewer']

export default function AdminUsers() {
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [showModal, setShowModal] = useState(false)
  const [editingUser, setEditingUser] = useState(null)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(null)
  
  const [form, setForm] = useState({
    username: '',
    email: '',
    password: '',
    role: 'operator',
    is_active: true,
  })

  const { data: users, isLoading } = useQuery({
    queryKey: ['users'],
    queryFn: () => usersApi.getAll(),
  })

  const createMutation = useMutation({
    mutationFn: usersApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      closeModal()
      toast.success('User created successfully')
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to create user')
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }) => usersApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      closeModal()
      toast.success('User updated successfully')
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to update user')
  })

  const deleteMutation = useMutation({
    mutationFn: usersApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      setShowDeleteConfirm(null)
      toast.success('User deleted successfully')
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to delete user')
  })

  const openCreate = () => {
    setEditingUser(null)
    setForm({ username: '', email: '', password: '', role: 'operator', is_active: true })
    setShowModal(true)
  }

  const openEdit = (user) => {
    setEditingUser(user)
    setForm({
      username: user.username,
      email: user.email,
      password: '',
      role: user.role,
      is_active: user.is_active,
    })
    setShowModal(true)
  }

  const closeModal = () => {
    setShowModal(false)
    setEditingUser(null)
    setForm({ username: '', email: '', password: '', role: 'operator', is_active: true })
  }

  const handleSubmit = (e) => {
    e.preventDefault()
    if (editingUser) {
      const updateData = { ...form }
      if (!updateData.password) delete updateData.password
      updateMutation.mutate({ id: editingUser.id, data: updateData })
    } else {
      createMutation.mutate(form)
    }
  }

  const filteredUsers = (Array.isArray(users) ? users : []).filter(user => 
    (user.username || '').toLowerCase().includes(search.toLowerCase()) ||
    (user.email || '').toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Users className="w-8 h-8 text-aegis-blue" />
            User Management
          </h1>
          <p className="text-gray-400 mt-1">Manage platform users and permissions</p>
        </div>
        <button onClick={openCreate} className="btn-primary flex items-center gap-2">
          <UserPlus className="w-4 h-4" />
          Add User
        </button>
      </div>

      {/* Search */}
      <div className="card p-4">
        <div className="relative max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search users..."
            className="input pl-10 w-full"
          />
        </div>
      </div>

      {/* Users Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-dark-800 border-b border-dark-700">
              <tr>
                <th className="text-left px-6 py-4 text-xs font-semibold text-gray-400 uppercase tracking-wider">User</th>
                <th className="text-left px-6 py-4 text-xs font-semibold text-gray-400 uppercase tracking-wider">Role</th>
                <th className="text-left px-6 py-4 text-xs font-semibold text-gray-400 uppercase tracking-wider">Status</th>
                <th className="text-left px-6 py-4 text-xs font-semibold text-gray-400 uppercase tracking-wider">Created</th>
                <th className="text-right px-6 py-4 text-xs font-semibold text-gray-400 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-700">
              {isLoading ? (
                <tr>
                  <td colSpan="5" className="px-6 py-12 text-center">
                    <Loader2 className="w-6 h-6 animate-spin text-aegis-blue mx-auto" />
                  </td>
                </tr>
              ) : filteredUsers.length === 0 ? (
                <tr>
                  <td colSpan="5" className="px-6 py-12 text-center text-gray-400">
                    No users found
                  </td>
                </tr>
              ) : (
                filteredUsers.map((user) => (
                  <tr key={user.id} className="hover:bg-dark-800/50">
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-full bg-aegis-blue/20 flex items-center justify-center">
                          <span className="text-aegis-blue font-semibold">
                            {user.username.charAt(0).toUpperCase()}
                          </span>
                        </div>
                        <div>
                          <div className="font-medium text-white">{user.username}</div>
                          <div className="text-sm text-gray-400 flex items-center gap-1">
                            <Mail className="w-3 h-3" />
                            {user.email}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${roleColors[user.role]}`}>
                        <Shield className="w-3 h-3" />
                        {user.role}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      {user.is_active ? (
                        <span className="inline-flex items-center gap-1.5 text-green-400 text-sm">
                          <CheckCircle className="w-4 h-4" />
                          Active
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-gray-400 text-sm">
                          <XCircle className="w-4 h-4" />
                          Inactive
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-400">
                      {format(new Date(user.created_at), 'MMM d, yyyy')}
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => openEdit(user)}
                          className="p-2 text-gray-400 hover:text-white hover:bg-dark-700 rounded-lg transition-colors"
                          title="Edit User"
                        >
                          <Edit2 className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => setShowDeleteConfirm(user)}
                          className="p-2 text-gray-400 hover:text-red-400 hover:bg-red-400/10 rounded-lg transition-colors"
                          title="Delete User"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create/Edit Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-900 rounded-xl border border-dark-700 w-full max-w-md">
            <div className="p-6 border-b border-dark-700">
              <h2 className="text-xl font-semibold text-white">
                {editingUser ? 'Edit User' : 'Add New User'}
              </h2>
            </div>
            
            <form onSubmit={handleSubmit} className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Full Name</label>
                <input
                  type="text"
                  value={form.username}
                  onChange={(e) => setForm({ ...form, username: e.target.value })}
                  className="input w-full"
                  placeholder="John Doe"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Email</label>
                <input
                  type="email"
                  value={form.email}
                  onChange={(e) => setForm({ ...form, email: e.target.value })}
                  className="input w-full"
                  placeholder="john@example.com"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  {editingUser ? 'New Password (leave blank to keep current)' : 'Password'}
                </label>
                <input
                  type="password"
                  value={form.password}
                  onChange={(e) => setForm({ ...form, password: e.target.value })}
                  className="input w-full"
                  placeholder="••••••••"
                  required={!editingUser}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Role</label>
                <select
                  value={form.role}
                  onChange={(e) => setForm({ ...form, role: e.target.value })}
                  className="input w-full"
                >
                  {roles.map((role) => (
                    <option key={role} value={role}>{role.charAt(0).toUpperCase() + role.slice(1)}</option>
                  ))}
                </select>
              </div>

              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={form.is_active}
                  onChange={(e) => setForm({ ...form, is_active: e.target.checked })}
                  className="w-4 h-4 rounded bg-dark-700 border-dark-600 text-aegis-blue focus:ring-aegis-blue"
                />
                <span className="text-gray-300">Account is active</span>
              </label>

              <div className="flex gap-3 pt-4">
                <button type="button" onClick={closeModal} className="btn-secondary flex-1">
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending || updateMutation.isPending}
                  className="btn-primary flex-1 flex items-center justify-center gap-2"
                >
                  {(createMutation.isPending || updateMutation.isPending) ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Saving...
                    </>
                  ) : (
                    editingUser ? 'Update User' : 'Create User'
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Confirmation */}
      {showDeleteConfirm && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-900 rounded-xl border border-dark-700 w-full max-w-md p-6">
            <h2 className="text-xl font-semibold text-white mb-2">Delete User</h2>
            <p className="text-gray-400 mb-6">
              Are you sure you want to delete <span className="text-white font-medium">{showDeleteConfirm.username}</span>? 
              This action cannot be undone.
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => setShowDeleteConfirm(null)}
                className="btn-secondary flex-1"
              >
                Cancel
              </button>
              <button
                onClick={() => deleteMutation.mutate(showDeleteConfirm.id)}
                disabled={deleteMutation.isPending}
                className="btn-primary bg-red-500 hover:bg-red-600 flex-1 flex items-center justify-center gap-2"
              >
                {deleteMutation.isPending ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Deleting...
                  </>
                ) : (
                  <>
                    <Trash2 className="w-4 h-4" />
                    Delete
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
