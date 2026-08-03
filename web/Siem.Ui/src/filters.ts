import type { Filters, RangePreset } from './types'

export const rangePresets: RangePreset[] = ['all', '1h', '24h', '7d', '30d', 'custom']

export const emptyFilters: Filters = {
  range: 'all', from: '', to: '', q: '', hostname: '', agent_id: '', destination_ip: '',
  destination_port: '', protocol: '', process_image: '', country_code: '', asn: '',
}

const allowedKeys = Object.keys(emptyFilters) as Array<keyof Filters>

function asLocalDateTime(value: string): string {
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return ''
  return new Date(parsed.getTime() - parsed.getTimezoneOffset() * 60000).toISOString().slice(0, 16)
}

export function filtersFromUrl(search: string): Filters {
  const values = new URLSearchParams(search)
  const result = { ...emptyFilters }
  const range = values.get('range')
  if (range && rangePresets.includes(range as RangePreset)) result.range = range as RangePreset
  for (const key of allowedKeys) {
    if (key === 'range') continue
    const value = values.get(key)
    if (value) result[key] = key === 'from' || key === 'to'
      ? asLocalDateTime(value)
      : value.slice(0, key === 'process_image' ? 260 : 160)
  }
  return result
}

export function filtersToSearch(filters: Filters): string {
  const values = new URLSearchParams()
  values.set('range', filters.range)
  for (const key of allowedKeys) {
    if (key === 'range') continue
    if (filters[key]) values.set(key, key === 'from' || key === 'to'
      ? new Date(filters[key]).toISOString()
      : filters[key])
  }
  return values.toString()
}

export function apiSearch(filters: Filters, now = new Date()): string {
  const values = new URLSearchParams()
  const hours: Partial<Record<RangePreset, number>> = { '1h': 1, '24h': 24, '7d': 168, '30d': 720 }
  if (filters.range === 'custom') {
    if (filters.from) values.set('from', new Date(filters.from).toISOString())
    if (filters.to) values.set('to', new Date(filters.to).toISOString())
  } else if (hours[filters.range]) {
    values.set('from', new Date(now.getTime() - hours[filters.range]! * 3600000).toISOString())
    values.set('to', now.toISOString())
  }
  for (const key of allowedKeys) {
    if (key === 'range' || key === 'from' || key === 'to') continue
    if (filters[key]) values.set(key === 'q' ? 'q' : key, filters[key])
  }
  values.set('limit', '2000')
  return values.toString()
}
