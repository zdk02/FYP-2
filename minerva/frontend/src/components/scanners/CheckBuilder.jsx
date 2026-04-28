import { Trash2, Plus } from 'lucide-react'

function Field({ name, field, value, onChange }) {
  const type = field?.type || 'string'
  if (type === 'array') {
    const joined = Array.isArray(value) ? value.join(', ') : value || ''
    return (
      <input
        className="input"
        placeholder={field.placeholder || `${name} (comma-separated)`}
        value={joined}
        onChange={(e) =>
          onChange(
            e.target.value
              .split(',')
              .map((v) => v.trim())
              .filter(Boolean)
              .map((v) => (field.items === 'integer' ? Number(v) : v))
          )
        }
      />
    )
  }
  return (
    <input
      className="input"
      type={type === 'integer' || type === 'number' ? 'number' : 'text'}
      min={field?.min}
      max={field?.max}
      placeholder={field?.placeholder || field?.default || ''}
      value={value ?? ''}
      onChange={(e) =>
        onChange(
          type === 'integer' || type === 'number'
            ? Number(e.target.value)
            : e.target.value
        )
      }
    />
  )
}

function CheckRow({ check, checkTypes, onChange, onRemove }) {
  const typeSchema = checkTypes.find((t) => t.type === check.type)
  const fields = typeSchema?.fields || {}
  const required = typeSchema?.required || []
  const allFields = Object.keys(fields)

  const updateField = (key, val) => {
    onChange({ ...check, [key]: val })
  }

  return (
    <div className="border border-dark-800 rounded-lg p-3 space-y-2 bg-dark-900/50">
      <div className="flex items-center gap-2">
        <select
          className="input appearance-none max-w-xs"
          value={check.type || ''}
          onChange={(e) => {
            const newType = e.target.value
            const schema = checkTypes.find((t) => t.type === newType)
            const next = { type: newType, description: check.description || '' }
            for (const f of schema?.required || []) {
              if (schema.fields[f]?.default !== undefined) {
                next[f] = schema.fields[f].default
              }
            }
            onChange(next)
          }}
        >
          <option value="">— select type —</option>
          {checkTypes.map((t) => (
            <option key={t.type} value={t.type}>
              {t.label || t.type}
            </option>
          ))}
        </select>
        <button
          onClick={onRemove}
          className="btn btn-ghost btn-sm ml-auto text-red-400 hover:text-red-300"
          title="Remove check"
        >
          <Trash2 className="w-4 h-4" />
        </button>
      </div>

      {check.type && (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {allFields.map((name) => {
              const field = fields[name]
              const isReq = required.includes(name)
              return (
                <div key={name}>
                  <label className="block text-[11px] text-dark-400 mb-0.5">
                    {name}
                    {isReq && <span className="text-red-400 ml-1">*</span>}
                  </label>
                  <Field
                    name={name}
                    field={field}
                    value={check[name]}
                    onChange={(v) => updateField(name, v)}
                  />
                </div>
              )
            })}
          </div>
          <div>
            <label className="block text-[11px] text-dark-400 mb-0.5">
              description
            </label>
            <input
              className="input"
              placeholder="What this check verifies"
              value={check.description || ''}
              onChange={(e) => updateField('description', e.target.value)}
            />
          </div>
        </>
      )}
    </div>
  )
}

export default function CheckBuilder({ checks = [], checkTypes = [], onChange }) {
  const add = () => onChange([...checks, { type: '' }])
  const updateAt = (idx, next) =>
    onChange(checks.map((c, i) => (i === idx ? next : c)))
  const removeAt = (idx) => onChange(checks.filter((_, i) => i !== idx))

  return (
    <div className="space-y-2">
      {checks.length === 0 && (
        <div className="text-xs text-dark-500 italic">No checks yet.</div>
      )}
      {checks.map((c, i) => (
        <CheckRow
          key={i}
          check={c}
          checkTypes={checkTypes}
          onChange={(next) => updateAt(i, next)}
          onRemove={() => removeAt(i)}
        />
      ))}
      <button
        onClick={add}
        className="btn btn-secondary btn-sm"
        type="button"
      >
        <Plus className="w-4 h-4" /> Add check
      </button>
    </div>
  )
}
