export type RangePreset = 'all' | '1h' | '24h' | '7d' | '30d' | 'custom'

export interface Filters {
  range: RangePreset
  from: string
  to: string
  q: string
  hostname: string
  agent_id: string
  destination_ip: string
  destination_port: string
  protocol: string
  process_image: string
  country_code: string
  asn: string
}

export interface Destination {
  destination_ip: string
  connection_observations: number
  baseline_observations: number
  new_observations: number
  change_events: number
  disappearance_events: number
  lifecycle_events: number
  packet_count_delta: number
  byte_count_delta: number
  first_seen_utc: string
  last_seen_utc: string
  protocols: string[]
  destination_ports: number[]
  hostnames: string[]
  agent_ids: string[]
  process_images: string[]
  evidence_modes: string[]
  directions: string[]
  geolocation_status: string
  latitude?: number
  longitude?: number
  city?: string
  region?: string
  country?: string
  country_code?: string
  continent?: string
  asn?: number
  organization?: string
  isp?: string
  geolocation_fetched_at_utc?: string
}

export interface GeographyResponse {
  schema_version: 'challenger-siem.network-geography.v2'
  retained_from_utc?: string
  retained_to_utc?: string
  from_utc?: string
  to_utc?: string
  generated_at_utc: string
  origin?: { label: string; latitude: number; longitude: number }
  map: { tile_url: string; attribution: string }
  geolocation_attribution?: { text: string; url: string }
  summary: {
    matched_lifecycle_events: number
    connection_observations: number
    unique_destinations: number
    returned_destinations: number
    geolocated_destinations: number
    pending_destinations: number
    unmapped_destinations: number
    quota_limited_destinations: number
    candidate_truncated: boolean
    result_truncated: boolean
  }
  destinations: Destination[]
  timeline: Array<{ start_utc: string; end_utc: string; connection_observations: number; lifecycle_events: number }>
  coverage: {
    source_id: string
    evidence_mode: string
    source_ids: string[]
    evidence_modes: string[]
    source_status_counts: Record<string, number>
    process_attribution_partial: boolean
  }
  active_filters: Array<{ name: string; value: string; protected: boolean }>
  result_scope: string
  limitations: string[]
}

export interface EventEnvelope {
  event_id: string
  agent_id: string
  hostname: string
  event_time: string
  event_code?: string
  severity: string
  message: string
  normalized?: {
    process_image?: string
    process?: { executable?: string }
    network?: { destination_port?: number; protocol?: string }
  }
}
