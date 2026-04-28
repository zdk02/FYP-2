import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { 
  FolderTree, Plus, Edit2, Trash2, ChevronRight, ChevronDown,
  Loader2, Folder, FolderOpen, Search, GripVertical
} from 'lucide-react'
import { categoriesApi, subcategoriesApi } from '../../services/api'
import toast from 'react-hot-toast'

export default function AdminCategories() {
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [expandedCategories, setExpandedCategories] = useState(new Set())
  const [showCategoryModal, setShowCategoryModal] = useState(false)
  const [showSubcategoryModal, setShowSubcategoryModal] = useState(false)
  const [editingCategory, setEditingCategory] = useState(null)
  const [editingSubcategory, setEditingSubcategory] = useState(null)
  const [parentCategory, setParentCategory] = useState(null)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(null)
  
  const [categoryForm, setCategoryForm] = useState({ name: '', description: '', icon: '', color: '#3b82f6' })
  const [subcategoryForm, setSubcategoryForm] = useState({ name: '', description: '' })

  const { data: categories, isLoading } = useQuery({
    queryKey: ['categories'],
    queryFn: () => categoriesApi.getAll(),
  })

  // Category mutations
  const createCategoryMutation = useMutation({
    mutationFn: categoriesApi.create,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['categories'] })
      closeCategoryModal()
      toast.success('Category created successfully')
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to create category')
  })

  const updateCategoryMutation = useMutation({
    mutationFn: ({ id, data }) => categoriesApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['categories'] })
      closeCategoryModal()
      toast.success('Category updated successfully')
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to update category')
  })

  const deleteCategoryMutation = useMutation({
    mutationFn: categoriesApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['categories'] })
      setShowDeleteConfirm(null)
      toast.success('Category deleted successfully')
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to delete category')
  })

  // Subcategory mutations
  const createSubcategoryMutation = useMutation({
    mutationFn: ({ categoryId, data }) => subcategoriesApi.create(categoryId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['categories'] })
      closeSubcategoryModal()
      toast.success('Subcategory created successfully')
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to create subcategory')
  })

  const updateSubcategoryMutation = useMutation({
    mutationFn: ({ id, data }) => subcategoriesApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['categories'] })
      closeSubcategoryModal()
      toast.success('Subcategory updated successfully')
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to update subcategory')
  })

  const deleteSubcategoryMutation = useMutation({
    mutationFn: (id) => subcategoriesApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['categories'] })
      setShowDeleteConfirm(null)
      toast.success('Subcategory deleted successfully')
    },
    onError: (error) => toast.error(error.response?.data?.error || 'Failed to delete subcategory')
  })

  const toggleExpand = (id) => {
    const newExpanded = new Set(expandedCategories)
    if (newExpanded.has(id)) {
      newExpanded.delete(id)
    } else {
      newExpanded.add(id)
    }
    setExpandedCategories(newExpanded)
  }

  const openCreateCategory = () => {
    setEditingCategory(null)
    setCategoryForm({ name: '', description: '', icon: '', color: '#3b82f6' })
    setShowCategoryModal(true)
  }

  const openEditCategory = (category) => {
    setEditingCategory(category)
    setCategoryForm({
      name: category.name,
      description: category.description || '',
      icon: category.icon || '',
      color: category.color || '#3b82f6',
    })
    setShowCategoryModal(true)
  }

  const closeCategoryModal = () => {
    setShowCategoryModal(false)
    setEditingCategory(null)
    setCategoryForm({ name: '', description: '', icon: '', color: '#3b82f6' })
  }

  const openCreateSubcategory = (category) => {
    setEditingSubcategory(null)
    setParentCategory(category)
    setSubcategoryForm({ name: '', description: '' })
    setShowSubcategoryModal(true)
  }

  const openEditSubcategory = (category, subcategory) => {
    setEditingSubcategory(subcategory)
    setParentCategory(category)
    setSubcategoryForm({
      name: subcategory.name,
      description: subcategory.description || '',
    })
    setShowSubcategoryModal(true)
  }

  const closeSubcategoryModal = () => {
    setShowSubcategoryModal(false)
    setEditingSubcategory(null)
    setParentCategory(null)
    setSubcategoryForm({ name: '', description: '' })
  }

  const handleCategorySubmit = (e) => {
    e.preventDefault()
    if (editingCategory) {
      updateCategoryMutation.mutate({ id: editingCategory.id, data: categoryForm })
    } else {
      createCategoryMutation.mutate(categoryForm)
    }
  }

  const handleSubcategorySubmit = (e) => {
    e.preventDefault()
    if (editingSubcategory) {
      updateSubcategoryMutation.mutate({ 
        id: editingSubcategory.id, 
        data: subcategoryForm 
      })
    } else {
      createSubcategoryMutation.mutate({ categoryId: parentCategory.id, data: subcategoryForm })
    }
  }

  const handleDelete = () => {
    if (showDeleteConfirm.type === 'category') {
      deleteCategoryMutation.mutate(showDeleteConfirm.item.id)
    } else {
      deleteSubcategoryMutation.mutate(showDeleteConfirm.item.id)
    }
  }

  const filteredCategories = (Array.isArray(categories) ? categories : []).filter(cat => 
    cat.name.toLowerCase().includes(search.toLowerCase()) ||
    cat.subcategories?.some(sub => sub.name.toLowerCase().includes(search.toLowerCase()))
  )

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <FolderTree className="w-8 h-8 text-aegis-blue" />
            Category Management
          </h1>
          <p className="text-gray-400 mt-1">Organize attacks into categories and subcategories</p>
        </div>
        <button onClick={openCreateCategory} className="btn-primary flex items-center gap-2">
          <Plus className="w-4 h-4" />
          Add Category
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
            placeholder="Search categories..."
            className="input pl-10 w-full"
          />
        </div>
      </div>

      {/* Categories Tree */}
      <div className="card">
        {isLoading ? (
          <div className="p-12 text-center">
            <Loader2 className="w-8 h-8 animate-spin text-aegis-blue mx-auto" />
          </div>
        ) : filteredCategories.length === 0 ? (
          <div className="p-12 text-center">
            <Folder className="w-12 h-12 text-gray-600 mx-auto mb-3" />
            <p className="text-gray-400">No categories yet</p>
            <button onClick={openCreateCategory} className="btn-primary mt-4">
              Create First Category
            </button>
          </div>
        ) : (
          <div className="divide-y divide-dark-700">
            {filteredCategories.map((category) => {
              const isExpanded = expandedCategories.has(category.id)
              return (
                <div key={category.id}>
                  {/* Category Row */}
                  <div className="p-4 flex items-center gap-4 hover:bg-dark-800/50">
                    <button
                      onClick={() => toggleExpand(category.id)}
                      className="p-1 text-gray-400 hover:text-white"
                    >
                      {isExpanded ? (
                        <ChevronDown className="w-5 h-5" />
                      ) : (
                        <ChevronRight className="w-5 h-5" />
                      )}
                    </button>
                    
                    <div 
                      className="p-2 rounded-lg"
                      style={{ backgroundColor: `${category.color}20` }}
                    >
                      {isExpanded ? (
                        <FolderOpen className="w-5 h-5" style={{ color: category.color }} />
                      ) : (
                        <Folder className="w-5 h-5" style={{ color: category.color }} />
                      )}
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="font-medium text-white">{category.name}</div>
                      {category.description && (
                        <div className="text-sm text-gray-400 truncate">{category.description}</div>
                      )}
                    </div>

                    <div className="text-sm text-gray-500">
                      {category.subcategories?.length || 0} subcategories
                    </div>

                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => openCreateSubcategory(category)}
                        className="p-2 text-gray-400 hover:text-aegis-blue hover:bg-aegis-blue/10 rounded-lg transition-colors"
                        title="Add Subcategory"
                      >
                        <Plus className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => openEditCategory(category)}
                        className="p-2 text-gray-400 hover:text-white hover:bg-dark-700 rounded-lg transition-colors"
                        title="Edit Category"
                      >
                        <Edit2 className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => setShowDeleteConfirm({ type: 'category', item: category })}
                        className="p-2 text-gray-400 hover:text-red-400 hover:bg-red-400/10 rounded-lg transition-colors"
                        title="Delete Category"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>

                  {/* Subcategories */}
                  {isExpanded && category.subcategories?.length > 0 && (
                    <div className="bg-dark-800/30 border-t border-dark-700">
                      {category.subcategories.map((subcategory) => (
                        <div
                          key={subcategory.id}
                          className="p-4 pl-16 flex items-center gap-4 hover:bg-dark-800/50 border-b border-dark-700/50 last:border-0"
                        >
                          <Folder className="w-4 h-4 text-gray-500" />
                          
                          <div className="flex-1 min-w-0">
                            <div className="font-medium text-gray-200">{subcategory.name}</div>
                            {subcategory.description && (
                              <div className="text-sm text-gray-500 truncate">{subcategory.description}</div>
                            )}
                          </div>

                          <div className="text-sm text-gray-500">
                            {subcategory.attacks_count || 0} attacks
                          </div>

                          <div className="flex items-center gap-1">
                            <button
                              onClick={() => openEditSubcategory(category, subcategory)}
                              className="p-2 text-gray-400 hover:text-white hover:bg-dark-700 rounded-lg transition-colors"
                              title="Edit Subcategory"
                            >
                              <Edit2 className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => setShowDeleteConfirm({ type: 'subcategory', item: subcategory, parent: category })}
                              className="p-2 text-gray-400 hover:text-red-400 hover:bg-red-400/10 rounded-lg transition-colors"
                              title="Delete Subcategory"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Category Modal */}
      {showCategoryModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-900 rounded-xl border border-dark-700 w-full max-w-md">
            <div className="p-6 border-b border-dark-700">
              <h2 className="text-xl font-semibold text-white">
                {editingCategory ? 'Edit Category' : 'Add New Category'}
              </h2>
            </div>
            
            <form onSubmit={handleCategorySubmit} className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Name</label>
                <input
                  type="text"
                  value={categoryForm.name}
                  onChange={(e) => setCategoryForm({ ...categoryForm, name: e.target.value })}
                  className="input w-full"
                  placeholder="e.g., MCP Attacks"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Description</label>
                <textarea
                  value={categoryForm.description}
                  onChange={(e) => setCategoryForm({ ...categoryForm, description: e.target.value })}
                  className="input w-full"
                  placeholder="Category description..."
                  rows={3}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Color</label>
                <div className="flex items-center gap-3">
                  <input
                    type="color"
                    value={categoryForm.color}
                    onChange={(e) => setCategoryForm({ ...categoryForm, color: e.target.value })}
                    className="w-12 h-10 rounded border border-dark-600 bg-dark-800 cursor-pointer"
                  />
                  <input
                    type="text"
                    value={categoryForm.color}
                    onChange={(e) => setCategoryForm({ ...categoryForm, color: e.target.value })}
                    className="input flex-1"
                    placeholder="#3b82f6"
                  />
                </div>
              </div>

              <div className="flex gap-3 pt-4">
                <button type="button" onClick={closeCategoryModal} className="btn-secondary flex-1">
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createCategoryMutation.isPending || updateCategoryMutation.isPending}
                  className="btn-primary flex-1 flex items-center justify-center gap-2"
                >
                  {(createCategoryMutation.isPending || updateCategoryMutation.isPending) ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Saving...
                    </>
                  ) : (
                    editingCategory ? 'Update' : 'Create'
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Subcategory Modal */}
      {showSubcategoryModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-900 rounded-xl border border-dark-700 w-full max-w-md">
            <div className="p-6 border-b border-dark-700">
              <h2 className="text-xl font-semibold text-white">
                {editingSubcategory ? 'Edit Subcategory' : 'Add Subcategory'}
              </h2>
              <p className="text-sm text-gray-400 mt-1">Under: {parentCategory?.name}</p>
            </div>
            
            <form onSubmit={handleSubcategorySubmit} className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Name</label>
                <input
                  type="text"
                  value={subcategoryForm.name}
                  onChange={(e) => setSubcategoryForm({ ...subcategoryForm, name: e.target.value })}
                  className="input w-full"
                  placeholder="e.g., Client-Side Attacks"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Description</label>
                <textarea
                  value={subcategoryForm.description}
                  onChange={(e) => setSubcategoryForm({ ...subcategoryForm, description: e.target.value })}
                  className="input w-full"
                  placeholder="Subcategory description..."
                  rows={3}
                />
              </div>

              <div className="flex gap-3 pt-4">
                <button type="button" onClick={closeSubcategoryModal} className="btn-secondary flex-1">
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createSubcategoryMutation.isPending || updateSubcategoryMutation.isPending}
                  className="btn-primary flex-1 flex items-center justify-center gap-2"
                >
                  {(createSubcategoryMutation.isPending || updateSubcategoryMutation.isPending) ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Saving...
                    </>
                  ) : (
                    editingSubcategory ? 'Update' : 'Create'
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
            <h2 className="text-xl font-semibold text-white mb-2">
              Delete {showDeleteConfirm.type === 'category' ? 'Category' : 'Subcategory'}
            </h2>
            <p className="text-gray-400 mb-6">
              Are you sure you want to delete <span className="text-white font-medium">{showDeleteConfirm.item.name}</span>?
              {showDeleteConfirm.type === 'category' && ' All subcategories will also be deleted.'}
            </p>
            <div className="flex gap-3">
              <button onClick={() => setShowDeleteConfirm(null)} className="btn-secondary flex-1">
                Cancel
              </button>
              <button
                onClick={handleDelete}
                disabled={deleteCategoryMutation.isPending || deleteSubcategoryMutation.isPending}
                className="btn-primary bg-red-500 hover:bg-red-600 flex-1 flex items-center justify-center gap-2"
              >
                {(deleteCategoryMutation.isPending || deleteSubcategoryMutation.isPending) ? (
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
