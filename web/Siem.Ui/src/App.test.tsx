import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'

vi.mock('react-leaflet', () => ({
  MapContainer: ({ children }: { children: React.ReactNode }) => <div data-testid="map">{children}</div>,
  TileLayer: () => null,
  CircleMarker: ({ children }: { children?: React.ReactNode }) => <div>{children}</div>,
  Polyline: () => null,
  Popup: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}))

const response = {
  schema_version: 'challenger-siem.network-geography.v2' as const,
  generated_at_utc: '2026-08-03T12:00:00Z',
  origin: { label: 'Synthetic origin', latitude: 0, longitude: 0 },
  map: { tile_url: 'https://tile.openstreetmap.org/{z}/{x}/{y}.png', attribution: 'Map' },
  summary: { matched_lifecycle_events: 1, connection_observations: 1, unique_destinations: 1, returned_destinations: 1, geolocated_destinations: 1, pending_destinations: 0, unmapped_destinations: 0, quota_limited_destinations: 0, candidate_truncated: false, result_truncated: false },
  destinations: [{ destination_ip: '203.0.113.10', connection_observations: 1, baseline_observations: 0, new_observations: 1, change_events: 0, disappearance_events: 0, lifecycle_events: 1, first_seen_utc: '2026-08-03T11:00:00Z', last_seen_utc: '2026-08-03T11:00:00Z', protocols: ['tcp'], destination_ports: [443], hostnames: ['synthetic-host'], agent_ids: ['synthetic-agent'], process_images: [], geolocation_status: 'ready', latitude: 1, longitude: 1, city: 'Example City', country: 'Example Country' }],
  timeline: [],
  coverage: { source_id: 'linux-network-socket-snapshot-diff', evidence_mode: 'snapshot_diff', source_status_counts: { healthy: 1 }, process_attribution_partial: true },
  active_filters: [], result_scope: 'synthetic', limitations: ['Synthetic limitation.'],
}

describe('App authentication boundary', () => {
  beforeEach(() => {
    window.history.replaceState(null, '', '/ui/traffic')
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => response }))
  })

  afterEach(() => cleanup())

  async function unlock() {
    render(<App />)
    fireEvent.change(screen.getByLabelText(/service bearer/i), { target: { value: 'synthetic-service-value' } })
    fireEvent.click(screen.getByRole('button', { name: /open map/i }))
    await waitFor(() => expect(screen.getByText('Network geography')).toBeInTheDocument())
  }

  it('keeps the token in memory and unlocks through an authenticated request', async () => {
    render(<App />)
    expect(screen.getByRole('heading', { name: /see the shape/i })).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText(/service bearer/i), { target: { value: 'synthetic-service-value' } })
    fireEvent.click(screen.getByRole('button', { name: /open map/i }))
    await waitFor(() => expect(screen.getByText('Network geography')).toBeInTheDocument())
    const call = vi.mocked(fetch).mock.calls[0]
    expect((call[1]?.headers as Record<string, string>).Authorization).toBe('Bearer synthetic-service-value')
    expect(window.location.search).not.toContain('synthetic-service-value')
    expect(localStorage.length).toBe(0)
    expect(sessionStorage.length).toBe(0)
  })

  it('cancels stale filter requests and keeps deep links credential-free', async () => {
    await unlock()
    fireEvent.change(screen.getByRole('searchbox', { name: /search network metadata/i }), { target: { value: '443' } })
    fireEvent.click(screen.getByRole('button', { name: 'Search' }))
    await waitFor(() => expect(vi.mocked(fetch).mock.calls.length).toBeGreaterThanOrEqual(2))
    const staleSignal = vi.mocked(fetch).mock.calls[1][1]?.signal as AbortSignal
    fireEvent.change(screen.getByRole('searchbox', { name: /search network metadata/i }), { target: { value: '53' } })
    fireEvent.click(screen.getByRole('button', { name: 'Search' }))
    await waitFor(() => expect(vi.mocked(fetch).mock.calls.length).toBeGreaterThanOrEqual(3))
    expect(staleSignal.aborted).toBe(true)
    expect(String(vi.mocked(fetch).mock.calls.at(-1)?.[0])).toContain('q=53')
    expect(window.location.search).toContain('q=53')
    expect(window.location.search).not.toContain('synthetic-service-value')
  })

  it('exposes an accessible destination table and drills into matching events', async () => {
    await unlock()
    const table = screen.getByRole('table', { name: /remote peer destinations/i })
    expect(within(table).getByRole('columnheader', { name: /peer/i })).toBeInTheDocument()
    fireEvent.click(within(table).getByRole('button', { name: /203\.0\.113\.10/i }))
    expect(await screen.findByRole('complementary', { name: /destination 203\.0\.113\.10/i })).toBeInTheDocument()
    await waitFor(() => expect(vi.mocked(fetch).mock.calls.some(call => String(call[0]).includes('/api/v2/events?') && String(call[0]).includes('destination_ip=203.0.113.10'))).toBe(true))
  })

  it('shows provider, truncation, and process-attribution degradation notices', async () => {
    const degraded = {
      ...response,
      summary: { ...response.summary, unmapped_destinations: 1, quota_limited_destinations: 1, result_truncated: true },
    }
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => degraded }))
    await unlock()
    expect(screen.getByText(/process attribution is partial/i)).toBeInTheDocument()
    expect(screen.getByText(/locations are unresolved/i)).toBeInTheDocument()
    expect(screen.getByText(/provider quota-limited/i)).toBeInTheDocument()
    expect(screen.getByText(/result bounds were reached/i)).toBeInTheDocument()
  })
})
