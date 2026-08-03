import { FormEvent, useEffect, useMemo, useRef, useState } from 'react'
import { CircleMarker, MapContainer, Polyline, Popup, TileLayer } from 'react-leaflet'
import type { Destination, EventEnvelope, Filters, GeographyResponse, RangePreset } from './types'
import { apiSearch, filtersFromUrl, filtersToSearch, rangePresets } from './filters'

const formatter = new Intl.NumberFormat()

function locationName(destination: Destination) {
  return [destination.city, destination.region, destination.country].filter(Boolean).join(', ') || 'Location unresolved'
}

function formatTime(value?: string) {
  return value ? new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : '—'
}

function Unlock({ onUnlock }: { onUnlock: (token: string) => Promise<void> }) {
  const [token, setToken] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      await onUnlock(token.trim())
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Could not unlock the interface.')
    } finally {
      setBusy(false)
    }
  }

  return <main className="unlock-shell">
    <section className="unlock-card" aria-labelledby="unlock-title">
      <div className="brand-mark" aria-hidden="true"><span /><span /><span /></div>
      <p className="eyebrow">Challenger SIEM · local visual aid</p>
      <h1 id="unlock-title">See the shape of your network evidence.</h1>
      <p className="unlock-copy">Unlock the read-only map with the existing service bearer. It is held in memory for this tab only and disappears on reload.</p>
      <form onSubmit={submit}>
        <label htmlFor="service-token">Service bearer</label>
        <div className="token-row">
          <input id="service-token" type="password" autoComplete="off" spellCheck={false} value={token} onChange={event => setToken(event.target.value)} placeholder="Paste service bearer" required />
          <button type="submit" disabled={busy || !token.trim()}>{busy ? 'Checking…' : 'Open map'}</button>
        </div>
        {error && <p role="alert" className="error-message">{error}</p>}
      </form>
      <div className="evidence-note"><strong>Evidence boundary</strong><span>Socket snapshots can miss short-lived peers and do not measure packets, bytes, or proven traffic direction.</span></div>
    </section>
  </main>
}

function Timeline({ data, onSelect }: { data: GeographyResponse['timeline']; onSelect: (from: string, to: string) => void }) {
  const maximum = Math.max(1, ...data.map(item => item.connection_observations))
  return <div className="timeline" aria-label="Connection observations over time">
    {data.map(item => <button
      type="button"
      key={item.start_utc}
      className="timeline-bar"
      style={{ height: `${Math.max(5, item.connection_observations / maximum * 100)}%` }}
      title={`${formatter.format(item.connection_observations)} observations · ${formatTime(item.start_utc)}`}
      aria-label={`Show ${formatTime(item.start_utc)} to ${formatTime(item.end_utc)}`}
      onClick={() => onSelect(item.start_utc, item.end_utc)}
    />)}
  </div>
}

function TrafficMap({ response, selected, onSelect }: { response: GeographyResponse; selected?: Destination; onSelect: (item: Destination) => void }) {
  const points = response.destinations.filter(item => item.latitude != null && item.longitude != null)
  const arcPoints = (selected ? [selected] : points.slice(0, 25)).filter(item => item.latitude != null && item.longitude != null)
  const origin = response.origin
  return <MapContainer center={[18, 8]} zoom={2} minZoom={2} maxZoom={12} scrollWheelZoom preferCanvas className="map-canvas" worldCopyJump>
    <TileLayer url={response.map.tile_url} attribution={response.map.attribution} keepBuffer={0} updateWhenIdle detectRetina={false} />
    {origin && <CircleMarker center={[origin.latitude, origin.longitude]} radius={7} pathOptions={{ color: '#e9f6b2', fillColor: '#c8ff47', fillOpacity: 1, weight: 2 }}>
      <Popup><strong>{origin.label}</strong><br />Configured approximate origin</Popup>
    </CircleMarker>}
    {origin && arcPoints.map(item => <Polyline key={`arc-${item.destination_ip}`} positions={[[origin.latitude, origin.longitude], [item.latitude!, item.longitude!]]} pathOptions={{ color: selected?.destination_ip === item.destination_ip ? '#c8ff47' : '#5ed8d2', opacity: selected ? .8 : .28, weight: selected ? 2 : 1, dashArray: '5 8' }} />)}
    {points.map(item => {
      const active = selected?.destination_ip === item.destination_ip
      return <CircleMarker
        key={item.destination_ip}
        center={[item.latitude!, item.longitude!]}
        radius={Math.min(18, 4 + Math.log2(item.connection_observations + 1) * 1.6)}
        pathOptions={{ color: active ? '#f5ffd9' : '#072d2c', fillColor: active ? '#c8ff47' : '#31c9be', fillOpacity: active ? 1 : .78, weight: active ? 3 : 1 }}
        eventHandlers={{ click: () => onSelect(item) }}
      >
        <Popup><strong>{item.destination_ip}</strong><br />{locationName(item)}<br />{formatter.format(item.connection_observations)} observations</Popup>
      </CircleMarker>
    })}
  </MapContainer>
}

function DetailPanel({ destination, events, loadingEvents, onClose }: { destination: Destination; events: EventEnvelope[]; loadingEvents: boolean; onClose: () => void }) {
  return <aside className="detail-panel" aria-label={`Destination ${destination.destination_ip}`}>
    <button className="close-button" type="button" onClick={onClose} aria-label="Close destination details">×</button>
    <p className="eyebrow">Remote peer</p>
    <h2>{destination.destination_ip}</h2>
    <p className="place-name">{locationName(destination)}</p>
    <div className="detail-metrics">
      <div><span>Observed</span><strong>{formatter.format(destination.connection_observations)}</strong></div>
      <div><span>First seen</span><strong>{formatTime(destination.first_seen_utc)}</strong></div>
      <div><span>Last seen</span><strong>{formatTime(destination.last_seen_utc)}</strong></div>
      <div><span>Geo status</span><strong>{destination.geolocation_status.replace('_', ' ')}</strong></div>
    </div>
    <dl className="metadata-list">
      <div><dt>Network</dt><dd>{destination.asn ? `AS${destination.asn}` : '—'} {destination.organization || destination.isp || ''}</dd></div>
      <div><dt>Ports</dt><dd>{destination.destination_ports.join(', ') || '—'}</dd></div>
      <div><dt>Protocols</dt><dd>{destination.protocols.join(', ') || '—'}</dd></div>
      <div><dt>Hosts</dt><dd>{destination.hostnames.join(', ') || '—'}</dd></div>
      <div><dt>Processes</dt><dd>{destination.process_images.join(', ') || 'Not attributed'}</dd></div>
      <div><dt>Lifecycle</dt><dd>{destination.new_observations} new · {destination.baseline_observations} baseline · {destination.change_events} changed · {destination.disappearance_events} disappeared</dd></div>
    </dl>
    <div className="event-section">
      <div className="section-heading"><h3>Newest evidence</h3><span>up to 25</span></div>
      {loadingEvents && <p className="muted">Loading matching records…</p>}
      {!loadingEvents && events.length === 0 && <p className="muted">No matching event records were returned.</p>}
      {events.map(event => <article className="event-card" key={`${event.agent_id}-${event.event_id}`}>
        <div><span className={`severity severity-${event.severity}`}>{event.severity}</span><time>{formatTime(event.event_time)}</time></div>
        <strong>{event.event_code || 'network event'}</strong>
        <p>{event.hostname} · {event.message}</p>
      </article>)}
    </div>
  </aside>
}

function App() {
  const [token, setToken] = useState<string | null>(null)
  const [filters, setFilters] = useState<Filters>(() => filtersFromUrl(window.location.search))
  const [draftSearch, setDraftSearch] = useState(filters.q)
  const [response, setResponse] = useState<GeographyResponse | null>(null)
  const [selected, setSelected] = useState<Destination>()
  const [events, setEvents] = useState<EventEnvelope[]>([])
  const [loading, setLoading] = useState(false)
  const [loadingEvents, setLoadingEvents] = useState(false)
  const [error, setError] = useState('')
  const [showFilters, setShowFilters] = useState(false)
  const [sort, setSort] = useState<'observations' | 'recent' | 'location'>('observations')
  const request = useRef<AbortController | undefined>(undefined)
  const skipLoadedQuery = useRef<string | undefined>(undefined)

  const query = useMemo(() => apiSearch(filters), [filters])
  const sorted = useMemo(() => response ? [...response.destinations].sort((left, right) => {
    if (sort === 'recent') return right.last_seen_utc.localeCompare(left.last_seen_utc)
    if (sort === 'location') return locationName(left).localeCompare(locationName(right))
    return right.connection_observations - left.connection_observations
  }) : [], [response, sort])

  async function load(activeToken: string, signal?: AbortSignal) {
    const result = await fetch(`/api/v2/network/geography?${query}`, { headers: { Authorization: `Bearer ${activeToken}` }, cache: 'no-store', redirect: 'error', signal })
    if (result.status === 401 || result.status === 403) throw new Error('The service bearer was not accepted.')
    if (result.status === 404) throw new Error('The traffic map is not enabled in local server configuration.')
    if (!result.ok) throw new Error(`The map request failed (${result.status}).`)
    return result.json() as Promise<GeographyResponse>
  }

  async function unlock(value: string) {
    const data = await load(value)
    skipLoadedQuery.current = query
    setToken(value)
    setResponse(data)
  }

  useEffect(() => {
    if (!token) return
    if (skipLoadedQuery.current === query) {
      skipLoadedQuery.current = undefined
      return
    }
    request.current?.abort()
    const controller = new AbortController()
    request.current = controller
    setLoading(true)
    setError('')
    load(token, controller.signal)
      .then(data => setResponse(data))
      .catch(reason => { if (reason.name !== 'AbortError') setError(reason.message) })
      .finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [token, query])

  useEffect(() => {
    const url = `${window.location.pathname}?${filtersToSearch(filters)}`
    window.history.replaceState(null, '', url)
  }, [filters])

  useEffect(() => {
    if (!selected || !response) return
    const updated = response.destinations.find(item => item.destination_ip === selected.destination_ip)
    if (!updated) setSelected(undefined)
    else if (updated !== selected) setSelected(updated)
  }, [response, selected])

  useEffect(() => {
    if (!token || !response?.summary.pending_destinations) return
    const controller = new AbortController()
    const timer = window.setTimeout(() => {
      load(token, controller.signal).then(setResponse).catch(() => undefined)
    }, 5000)
    return () => { window.clearTimeout(timer); controller.abort() }
  }, [token, response])

  useEffect(() => {
    if (!selected || !token) { setEvents([]); return }
    const controller = new AbortController()
    const values = new URLSearchParams({ destination_ip: selected.destination_ip, source_id: 'linux-network-socket-snapshot-diff', limit: '25' })
    const geography = new URLSearchParams(query)
    if (geography.get('from')) values.set('from', geography.get('from')!)
    if (geography.get('to')) values.set('to', geography.get('to')!)
    setLoadingEvents(true)
    setEvents([])
    fetch(`/api/v2/events?${values}`, { headers: { Authorization: `Bearer ${token}` }, cache: 'no-store', redirect: 'error', signal: controller.signal })
      .then(result => result.ok ? result.json() : Promise.reject(new Error('Event drill-down failed.')))
      .then(data => setEvents(data.events || []))
      .catch(reason => { if (reason.name !== 'AbortError') setEvents([]) })
      .finally(() => { if (!controller.signal.aborted) setLoadingEvents(false) })
    return () => controller.abort()
  }, [selected, token, query])

  function selectRange(range: RangePreset) {
    setFilters(current => ({ ...current, range, ...(range === 'custom' ? {} : { from: '', to: '' }) }))
  }

  function submitSearch(event: FormEvent) {
    event.preventDefault()
    setFilters(current => ({ ...current, q: draftSearch.trim() }))
  }

  function timelineSelect(from: string, to: string) {
    const local = (value: string) => {
      const date = new Date(value)
      return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16)
    }
    setFilters(current => ({ ...current, range: 'custom', from: local(from), to: local(to) }))
  }

  if (!token) return <Unlock onUnlock={unlock} />

  return <div className="app-shell">
    <header className="topbar">
      <div className="brand"><div className="brand-mark small" aria-hidden="true"><span /><span /><span /></div><div><strong>Challenger SIEM</strong><span>Network geography</span></div></div>
      <form className="search" onSubmit={submitSearch} role="search">
        <label className="sr-only" htmlFor="global-search">Search network metadata</label>
        <input id="global-search" type="search" value={draftSearch} onChange={event => setDraftSearch(event.target.value)} placeholder="Search IP, country, ASN, port, host or process" />
        <button type="submit">Search</button>
      </form>
      <button className="ghost-button" type="button" onClick={() => setToken(null)}>Lock</button>
    </header>

    <section className="control-strip" aria-label="Time and metadata filters">
      <div className="range-buttons">{rangePresets.map(range => <button type="button" className={filters.range === range ? 'active' : ''} key={range} onClick={() => selectRange(range)}>{range === 'all' ? 'All retained' : range === 'custom' ? 'Custom' : range}</button>)}</div>
      {filters.range === 'custom' && <div className="custom-range">
        <label>From <input type="datetime-local" value={filters.from} onChange={event => setFilters(current => ({ ...current, from: event.target.value }))} /></label>
        <label>To <input type="datetime-local" value={filters.to} onChange={event => setFilters(current => ({ ...current, to: event.target.value }))} /></label>
      </div>}
      <button className="filter-toggle" type="button" aria-expanded={showFilters} onClick={() => setShowFilters(value => !value)}>{showFilters ? 'Hide filters' : 'More filters'}</button>
    </section>

    {showFilters && <section className="filter-panel">
      {([
        ['hostname', 'Hostname'], ['agent_id', 'Agent ID'], ['destination_ip', 'Remote IP'], ['destination_port', 'Port'],
        ['process_image', 'Process'], ['country_code', 'Country code'], ['asn', 'ASN'],
      ] as Array<[keyof Filters, string]>).map(([key, label]) => <label key={key}>{label}<input value={filters[key]} onChange={event => setFilters(current => ({ ...current, [key]: event.target.value }))} /></label>)}
      <label>Protocol<select value={filters.protocol} onChange={event => setFilters(current => ({ ...current, protocol: event.target.value }))}><option value="">Any</option><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
    </section>}

    {error && <div className="banner error-banner" role="alert">{error}</div>}
    {response && <>
      <section className="summary-strip">
        <div><span>Remote peers</span><strong>{formatter.format(response.summary.unique_destinations)}</strong></div>
        <div><span>Connection observations</span><strong>{formatter.format(response.summary.connection_observations)}</strong></div>
        <div><span>Geolocated</span><strong>{formatter.format(response.summary.geolocated_destinations)}</strong></div>
        <div><span>Pending / unmapped</span><strong>{formatter.format(response.summary.pending_destinations)} / {formatter.format(response.summary.unmapped_destinations)}</strong></div>
        <div className="retention"><span>Retained evidence</span><strong>{formatTime(response.retained_from_utc)} → {formatTime(response.retained_to_utc)}</strong></div>
      </section>

      <main className="workspace">
        <section className="map-panel" aria-label="Geographic network observation map">
          {loading && <div className="loading-overlay">Refreshing evidence…</div>}
          <TrafficMap response={response} selected={selected} onSelect={setSelected} />
          <div className="map-legend"><span><i className="origin-dot" /> configured origin</span><span><i className="peer-dot" /> geolocated peer</span></div>
          {(response.summary.pending_destinations > 0 || response.summary.quota_limited_destinations > 0) && <div className="map-status">{response.summary.pending_destinations > 0 && `${response.summary.pending_destinations} locations enriching`} {response.summary.quota_limited_destinations > 0 && `· ${response.summary.quota_limited_destinations} quota-limited`}</div>}
        </section>

        <section className="data-panel">
          <div className="timeline-wrap">
            <div className="section-heading"><div><p className="eyebrow">Selected evidence</p><h2>Observation timeline</h2></div><span>Click a bar to isolate its interval</span></div>
            <Timeline data={response.timeline} onSelect={timelineSelect} />
          </div>
          <div className="table-heading"><div><p className="eyebrow">Remote peers</p><h2>{formatter.format(response.destinations.length)} destinations</h2></div><label>Sort<select value={sort} onChange={event => setSort(event.target.value as typeof sort)}><option value="observations">Most observed</option><option value="recent">Most recent</option><option value="location">Location</option></select></label></div>
          <div className="table-scroll">
            <table className="destination-table" aria-label="Remote peer destinations">
              <thead><tr><th scope="col">Peer / location</th><th scope="col">Network metadata</th><th scope="col">Observed</th><th scope="col">Last seen</th></tr></thead>
              <tbody>{sorted.map(item => <tr className={selected?.destination_ip === item.destination_ip ? 'selected' : ''} key={item.destination_ip}>
                <td><button type="button" className="destination-select" aria-pressed={selected?.destination_ip === item.destination_ip} onClick={() => setSelected(item)}><strong>{item.destination_ip}</strong><small>{locationName(item)}</small></button></td>
                <td><span className="cell-stack"><strong>{item.asn ? `AS${item.asn}` : item.geolocation_status.replace('_', ' ')}</strong><small>{item.organization || item.protocols.join(', ') || 'No network owner metadata'}</small></span></td>
                <td><span className="cell-stack"><strong>{formatter.format(item.connection_observations)}</strong><small>{item.destination_ports.slice(0, 4).join(', ') || 'No port'}</small></span></td>
                <td><span className="cell-stack"><strong>{formatTime(item.last_seen_utc)}</strong><small>{item.hostnames[0] || item.agent_ids[0] || 'Unknown host'}</small></span></td>
              </tr>)}</tbody>
            </table>
          </div>
        </section>

        {selected && <DetailPanel destination={selected} events={events} loadingEvents={loadingEvents} onClose={() => setSelected(undefined)} />}
      </main>

      <footer className="evidence-footer">
        <div><strong>{response.coverage.evidence_mode.replace('_', ' ')} evidence</strong><span>{Object.entries(response.coverage.source_status_counts).map(([key, value]) => `${value} ${key}`).join(' · ') || 'source health unavailable'}</span></div>
        <p>{response.limitations.join(' ')}</p>
        <div className="footer-warnings" role="status">
          {(response.summary.candidate_truncated || response.summary.result_truncated) && <strong>Result bounds were reached; rows are a bounded view.</strong>}
          {response.coverage.process_attribution_partial && <strong>Process attribution is partial for this result.</strong>}
          {response.summary.unmapped_destinations > 0 && <strong>{response.summary.unmapped_destinations} locations are unresolved or locally excluded.</strong>}
          {response.summary.quota_limited_destinations > 0 && <strong>{response.summary.quota_limited_destinations} locations are provider quota-limited.</strong>}
        </div>
      </footer>
    </>}
  </div>
}

export default App
