import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import {
  Search,
  Filter,
  ChevronRight,
  ChevronDown,
  Folder,
  FolderOpen,
  FileCode,
  Shield,
  AlertTriangle,
  Clock,
  Tag,
  Plus,
} from 'lucide-react'
import { categoriesApi, attacksApi } from '../services/api'
import { useAuthStore } from '../stores/authStore'

const severityColors = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
  info: 'badge-info',
}

function CategoryTree({ categories, selectedId, onSelect }) {
  const [expanded, setExpanded] = useState({})

  const toggleExpand = (id) => {
    setExpanded(prev => ({ ...prev, [id]: !prev[id] }))
  }

  return (
    <div className="space-y-1">
      <button
        onClick={() => onSelect(null)}
        className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors
          ${selectedId === null ? 'bg-aegis-600/20 text-aegis-400' : 'text-dark-300 hover:bg-dark-800'}`}
      >
        <Shield className="w-4 h-4" />
        All Attacks
      </button>
      
      {categories?.map((category) => (
        <div key={category.id}>
          <button
            onClick={() => toggleExpand(category.id)}
            className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-dark-300 hover:bg-dark-800 transition-colors"
          >
            {expanded[category.id] ? (
              <>
                <ChevronDown className="w-4 h-4" />
                <FolderOpen className="w-4 h-4 text-aegis-400" />
              </>
            ) : (
              <>
                <ChevronRight className="w-4 h-4" />
                <Folder className="w-4 h-4" />
              </>
            )}
            <span className="flex-1 text-left truncate">{category.name}</span>
            <span className="text-xs text-dark-500">{category.attack_count || 0}</span>
          </button>
          
          {expanded[category.id] && category.subcategories && (
            <div className="ml-4 space-y-0.5">
              {category.subcategories.map((sub) => (
                <button
                  key={sub.id}
                  onClick={() => onSelect(sub.id)}
                  className={`w-full flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm transition-colors
                    ${selectedId === sub.id ? 'bg-aegis-600/20 text-aegis-400' : 'text-dark-400 hover:bg-dark-800 hover:text-dark-200'}`}
                >
                  <FileCode className="w-3 h-3" />
                  <span className="flex-1 text-left truncate">{sub.name}</span>
                  <span className="text-xs text-dark-500">{sub.attack_count || 0}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

function AttackCard({ attack }) {
  return (
    <Link
      to={`/attacks/${attack.id}`}
      className="card p-4 hover:border-dark-600 transition-all group"
    >
      <div className="flex items-start justify-between mb-3">
        <h3 className="font-medium text-white group-hover:text-aegis-400 transition-colors">
          {attack.name}
        </h3>
        <span className={`badge ${severityColors[attack.severity]}`}>
          {attack.severity}
        </span>
      </div>
      
      <p className="text-sm text-dark-400 line-clamp-2 mb-4">
        {attack.description}
      </p>
      
      <div className="flex items-center justify-between text-xs text-dark-500">
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1">
            <Tag className="w-3 h-3" />
            {attack.attack_type}
          </span>
          {attack.is_verified && (
            <span className="flex items-center gap-1 text-emerald-400">
              <Shield className="w-3 h-3" />
              Verified
            </span>
          )}
        </div>
        <span className="flex items-center gap-1">
          <Clock className="w-3 h-3" />
          {attack.estimated_duration}s
        </span>
      </div>
    </Link>
  )
}

export default function Attacks() {
  const { isAdmin } = useAuthStore()
  const [searchParams, setSearchParams] = useSearchParams()
  const [search, setSearch] = useState('')
  const [selectedSubcategory, setSelectedSubcategory] = useState(null)
  const [severityFilter, setSeverityFilter] = useState('')

  // Fetch categories
  const { data: categoriesData } = useQuery({
    queryKey: ['categories'],
    queryFn: () => categoriesApi.getAll(true),
  })

  // Fetch attacks
  const { data: attacksData, isLoading } = useQuery({
    queryKey: ['attacks', { subcategory_id: selectedSubcategory, severity: severityFilter, search }],
    queryFn: () => attacksApi.getAll({
      subcategory_id: selectedSubcategory,
      severity: severityFilter || undefined,
      search: search || undefined,
    }),
  })

  const categories = Array.isArray(categoriesData) ? categoriesData : []
  const attacks = Array.isArray(attacksData) ? attacksData : []

  return (
    <div className="flex gap-6 h-[calc(100vh-8rem)]">
      {/* Sidebar - Category Tree */}
      <div className="w-64 flex-shrink-0 card overflow-hidden flex flex-col">
        <div className="card-header">
          <h2 className="font-semibold text-white">Categories</h2>
        </div>
        <div className="flex-1 overflow-y-auto p-3">
          <CategoryTree
            categories={categories}
            selectedId={selectedSubcategory}
            onSelect={setSelectedSubcategory}
          />
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold text-white">Attack Library</h1>
            <p className="text-dark-400 mt-1">
              {attacks.length} attacks available
            </p>
          </div>
          {isAdmin() && (
            <Link to="/admin/categories" className="btn-primary">
              <Plus className="w-4 h-4" />
              Manage Attacks
            </Link>
          )}
        </div>

        {/* Filters */}
        <div className="flex items-center gap-4 mb-6">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-500" />
            <input
              type="text"
              placeholder="Search attacks..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="input pl-10"
            />
          </div>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="select w-40"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>

        {/* Attack Grid */}
        <div className="flex-1 overflow-y-auto">
          {isLoading ? (
            <div className="flex items-center justify-center h-64">
              <div className="spinner w-8 h-8" />
            </div>
          ) : attacks.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-64 text-dark-400">
              <AlertTriangle className="w-12 h-12 mb-4" />
              <p>No attacks found</p>
              <p className="text-sm text-dark-500">Try adjusting your filters</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              {attacks.map((attack) => (
                <AttackCard key={attack.id} attack={attack} />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
