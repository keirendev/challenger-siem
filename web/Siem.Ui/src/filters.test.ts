import { describe, expect, it } from 'vitest'
import { apiSearch, filtersFromUrl, filtersToSearch } from './filters'

describe('traffic-map filters', () => {
  it('round-trips supported deep-link filters without credentials', () => {
    const filters = filtersFromUrl('?range=7d&destination_ip=203.0.113.9&country_code=AU&authorization=secret')
    const search = filtersToSearch(filters)
    expect(filters.range).toBe('7d')
    expect(filters.destination_ip).toBe('203.0.113.9')
    expect(search).toContain('country_code=AU')
    expect(search).not.toContain('authorization')
    expect(search).not.toContain('secret')
  })

  it('translates presets and custom local values to UTC API bounds', () => {
    const preset = apiSearch({ ...filtersFromUrl(''), range: '24h' }, new Date('2026-08-03T12:00:00Z'))
    const presetValues = new URLSearchParams(preset)
    expect(presetValues.get('from')).toBe('2026-08-02T12:00:00.000Z')
    expect(presetValues.get('to')).toBe('2026-08-03T12:00:00.000Z')

    const custom = apiSearch({ ...filtersFromUrl(''), range: 'custom', from: '2026-08-01T10:00', to: '2026-08-01T11:00' })
    expect(new URLSearchParams(custom).get('from')).toMatch(/^2026-08-01T/)

    const hydrated = filtersFromUrl('?range=custom&from=2026-08-01T10%3A00%3A00Z&to=2026-08-01T11%3A00%3A00Z')
    const roundTrip = new URLSearchParams(filtersToSearch(hydrated))
    expect(roundTrip.get('from')).toMatch(/Z$/)
    expect(roundTrip.get('to')).toMatch(/Z$/)
  })
})
