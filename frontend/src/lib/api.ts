/**
 * KryxAI API client.
 *
 * The backend is passive: it analyses captures that already exist. There is no
 * websocket stream and no live monitor, so this client is request/response only
 * and every surface reflects a completed scan rather than a running one.
 */

export type Lang = 'en' | 'hi'

export interface ScanSummary {
  scan_id: string
  block_index: number | null
  posture_grade: string
  posture_score: number
  findings: number
  sessions: number
  chain_state: string
  report_files: Record<string, string>
}

export interface RiskContribution {
  label: string
  points: number
  rationale?: string
}

export interface Risk {
  total: number
  priority: string
  /** Ordering heuristic, not a probability. See {@link Finding.weight}. */
  weight: number
  /** 'onnx' when a model contributed, 'rules' when the rules scored alone. */
  model: string
  /**
   * Both component scores are recorded so the fused `total` can be checked
   * rather than trusted. `rule_score` is always present; `model_score` is null
   * when no model is configured, in which case `total` equals `rule_score`.
   */
  rule_score?: number
  model_score?: number | null
  contributions?: RiskContribution[]
}

export interface ModelInfo {
  status: string
  used: boolean
  feature_schema_version: number
  feature_count: number
  model_schema_version: number | null
  rule_score_mean: number | null
  model_score_mean: number | null
  sessions_scored?: number
  sessions_total?: number
  findings_scored?: number
  /**
   * Number of sessions whose inputs fell outside the training range and were
   * clamped before scoring. Reported so an unusual capture is not mistaken for
   * a clean one (see clamped_features).
   */
  sessions_with_clamped_features?: number
  /** Feature names clamped on at least one session because they were outside the training range. */
  clamped_features?: string[]
  /** Feature names that had zero variance in training, so the model learned nothing from them. */
  constant_training_features?: string[]
  /** False until the model card supplies a per-feature training range. */
  feature_ranges_known?: boolean
  note?: string
}

export interface Finding {
  finding_id: string
  code: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  title: string
  title_hi?: string
  detail: string
  endpoint?: string
  session_id?: string
  reference?: string
  remediation?: string
  /**
   * Detection weight: a hand-set 0-1 ordering heuristic for how strongly the
   * detector asserts this finding. NOT a probability — 0.9 does not mean a 90%
   * chance the finding is real.
   */
  weight?: number
  evidence?: Record<string, unknown>
  deliverable?: string
  risk?: Risk
}

export interface StartTlsInfo {
  state: string
  advertised: boolean
  upgrade_attempted: boolean
  server_ready: boolean
  tls_established: boolean
  encrypted_bytes: number
  signatures: string[]
  obfuscated_tokens?: string[]
  cross_flow_inconsistent: boolean
  confidence: number
  remediation: string
  downgrade: boolean
}

export interface TlsInfo {
  version?: string
  cipher_suite?: string
  key_exchange_group?: string
  signature_algorithm?: string
  alpn?: string[]
  sni?: string
  forward_secrecy?: boolean
  certificate_visible: boolean
  version_rating?: string
  cipher_rating?: string
  group_rating?: string
  signature_rating?: string
  worst_rating?: string
  not_assessed: string[]
  certificates: unknown[]
  chain: unknown[]
}

export interface MailSession {
  session_id: string
  endpoint: string
  peer: string
  protocol: 'SMTP' | 'IMAP' | 'POP3' | string
  port: number
  protocol_confidence: number
  protocol_signals: string[]
  starttls: StartTlsInfo
  tls: TlsInfo | null
  /**
   * The model's score for this session, or null when no model is configured.
   * Always present: the field is emitted with a null value on a rules-only
   * install so consumers can rely on the key existing.
   */
  model_score?: number | null
  first_seen: number
  last_seen: number
  bytes: { client: number; server: number }
  reassembly: {
    client_gaps: string[]
    server_gaps: string[]
    retransmit_bytes: number
    out_of_order_segments: number
    complete: boolean
  }
}

export interface PostureDimensionExplanation {
  value: number
  weight: number
  /** The points this dimension contributed to the overall posture score. */
  points: number
  /** How many sessions/certificates the dimension was measured over. */
  measured: number
  /** Human-readable reason this dimension has the value it has. */
  rationale: string
  not_assessed: boolean
}

export interface Posture {
  score: number
  grade: string
  label: string
  dimensions: Record<string, number>
  weights: Record<string, number>
  /** Per-dimension "why", so the posture is explainable not just a number. */
  dimension_explanation?: Record<string, PostureDimensionExplanation>
  not_assessed: string[]
  sessions_measured: number
  mail_sessions_measured: number
}

export interface ChainBlock {
  index: number
  hash: string
  prev_hash: string
  difficulty: number
  anchored: boolean
  anchor_tx: string | null
  anchor_provider: string | null
  created_at: string
}

export interface EvidenceInfo {
  scan_id: string
  block_index: number | null
  block_hash?: string
  chain_id: string
  chain_state: 'pending' | 'anchored' | 'demo' | string
  external_anchor?: boolean
}

export interface Report {
  tool: string
  version: string
  chain_id: string
  report_aad: string
  source: { path: string; sha256: string; size_bytes?: number }
  capture: Record<string, unknown>
  sessions: MailSession[]
  findings: Finding[]
  counts: {
    sessions: number
    mail_sessions: number
    tls_sessions: number
    tls_upgraded: number
    findings: number
    by_severity: Record<string, number>
    by_deliverable?: Record<string, number>
  }
  /**
   * Requirement coverage derived from this scan's own evidence. Present on
   * every report; the field is optional only so a cached report written by an
   * older build still typechecks.
   */
  coverage?: Coverage
  /**
   * Passive evidence that a STARTTLS/STLS advertisement was altered in the path.
   * Optional for the same reason as `coverage`: a report cached by an older
   * build predates the field and must still typecheck.
   */
  interception?: InterceptionEvidence
  /**
   * Whether the operator was actually notified about this scan's serious
   * findings. Optional for the same reason as `coverage` and `interception`:
   * a report cached by an older build predates the field.
   *
   * The panel that reads this renders nothing at all when the field is absent,
   * rather than showing a quiet green "notified" - a missing field is a gap,
   * not a success.
   */
  alerts?: AlertReport
  posture: Posture
  anomalies: unknown[]
  compliance: ComplianceSummary
  ioc: Record<string, unknown>
  model: ModelInfo
  limitations: string[]
  scan_seconds: number
  evidence: EvidenceInfo
}

/** One piece of structural evidence, e.g. K1. */
export interface InterceptionSignature {
  code: string
  title: string
  reference: string
  mechanism: string
  why_it_matters: string
}

export interface InterceptionSession {
  session_id: string
  endpoint: string
  protocol: string
  port: number
  state: string
  /** The token the protocol defines, e.g. STARTTLS for SMTP, STLS for POP3. */
  expected_token: string
  /**
   * What actually occupied the upgrade slot. `null` when nothing was
   * substituted: an empty array here would read as a finding rather than a pass.
   */
  observed_tokens: string[] | null
  advertised: boolean
  tls_established: boolean
  encrypted_bytes: number
  downgrade: boolean
  signatures: string[]
  signature_details: InterceptionSignature[]
  confidence: number
  remediation: string
  anomalies: string[]
}

export type InterceptionVerdict =
  | 'tampered_advertisement'
  | 'unencrypted_but_unmodified'
  | 'no_evidence_of_interception'

export interface InterceptionEvidence {
  verdict: InterceptionVerdict
  headline: string
  sessions_assessed: number
  sessions_tampered: number
  sessions_upgraded: number
  sessions_cleartext: number
  sessions: InterceptionSession[]
  /** Stated on the record: a capture cannot tell hostile from misconfigured. */
  attribution_limit: string
  /** Why a passive observer can make this claim when a live scanner cannot. */
  why_passive: string
  reference: string
}

/**
 * One attempt to notify one channel.
 *
 * `target` is a redaction produced by the backend, never the configured value:
 * a Telegram target reads `bot<redacted>`, so nothing replayable travels into
 * a report.
 */
export interface AlertDelivery {
  channel: string
  target: string
  status: 'sent' | 'failed'
  attempts: number
  error: string | null
}

export interface AlertReport {
  enabled: boolean
  min_severity: string
  triggered: boolean
  channels_configured: string[]
  deliveries: AlertDelivery[]
  /** Delivery records with a non-`sent` status. Non-empty means nobody was told. */
  failures: AlertDelivery[]
  /** Why nothing was sent, when nothing was. */
  skipped_reason: string | null
  note: string
}

/**
 * A requirement from the brief, and the evidence this scan produced for it.
 *
 * Three states, deliberately distinct. `demonstrated` means a finding or an
 * extracted artefact proves it. `clean` means it was evaluated across the
 * sessions and nothing adverse was found, which is the desired outcome and not
 * a missing feature. `not_demonstrated` means the engine supports it but this
 * capture contains nothing that exercises it.
 *
 * A clean capture therefore shows mostly `clean` rows, and that is the honest
 * reading: it is a clean capture.
 */
export type CoverageStatus = 'demonstrated' | 'clean' | 'not_demonstrated'

export interface CoverageItem {
  requirement: string
  status: CoverageStatus
  detail: string
  /** Specific witnesses: finding codes with endpoints, certs, negotiated values. */
  evidence: string[]
}

export interface Coverage {
  items: CoverageItem[]
  summary: Record<CoverageStatus, number>
  total: number
  /** Finding codes grouped by the brief's deliverable tag. */
  by_deliverable: Record<string, string[]>
  /** Filenames, present once the report has been rendered. */
  report_files?: Record<string, string>
}

export interface LegalProvision {
  key: string
  act: string
  section: string
  heading: string
  text: string
  url: string
  relevance: string
  penalty: string | null
  penalty_schedule: string | null
}

export interface ComplianceItem {
  finding_code: string
  severity: string
  endpoint: string | null
  provision: LegalProvision
  observation: string
  exposure: string
  caveats: string[]
  disclaimer: string
}

export interface ComplianceSummary {
  framework: string
  source: string
  mapped_findings: number
  by_section: Record<string, number>
  second_schedule: string
  second_schedule_note: string
  /**
   * 'UNVERIFIED_IN_THIS_BUILD' in this build: the statutory text is quoted from
   * a data file, not re-checked against the Gazette. Surfaced so the caveat
   * travels with the mapping into the signed report and the UI.
   */
  verification_status: string
  verification_note?: string
  authoritative_sources?: string[]
  provisions: LegalProvision[]
  items: ComplianceItem[]
  disclaimer: string
}

export interface Capabilities {
  protocols: string[]
  passive_only: boolean
  starttls_signatures: string[]
  tls_versions_visible: Record<string, string>
  statutes: string[]
  ioc: Record<string, unknown>
  known_limitations: string[]
}

export interface Health {
  status: string
  version: string
  chain_id: string
  anchor_required: boolean
  external_anchor: boolean
  alert_channels: string[]
  /** False means the scan ran with notification switched off entirely. */
  alerts_enabled: boolean
  /** Findings below this severity never notify. */
  alert_min_severity: string
}

export interface ChainStatus {
  ok: boolean
  chain_id: string
  broken_at?: number | null
  /** Number of blocks in the chain. */
  block_count: number
  /** The blocks themselves, oldest first. */
  blocks: ChainBlock[]
  details?: ChainBlock[]
}

export class ApiError extends Error {
  status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

/**
 * Ports the Vite dev server uses. On these the request is same-origin so the
 * dev proxy handles it, which keeps CORS out of the picture entirely. The set
 * must match the dev ports in vite.config.ts.
 */
const DEV_PORTS = new Set(['5173', '5174', '4173'])

function base(): string {
  const env = (import.meta as any).env ?? {}
  const explicit = env.VITE_API_BASE
  if (typeof explicit === 'string' && explicit.trim()) {
    return explicit.trim().replace(/\/+$/, '')
  }
  if (typeof window !== 'undefined' && DEV_PORTS.has(window.location.port)) {
    return ''
  }
  return ''
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response
  try {
    res = await fetch(`${base()}${path}`, init)
  } catch {
    throw new ApiError(
      `Cannot reach the KryxAI API at ${base() || window.location.origin}. ` +
        'Start it with `uvicorn kryxai.api:app`.',
      0,
    )
  }
  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = await res.json()
      if (body?.detail) detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(detail, res.status)
  }
  return (await res.json()) as T
}

export const api = {
  base,
  health: () => request<Health>('/health'),
  capabilities: () => request<Capabilities>('/api/v1/capabilities'),
  chain: () => request<ChainStatus>('/api/v1/chain'),

  scanPath: (path: string, opts: { sign?: boolean; langs?: Lang[] } = {}) =>
    request<ScanSummary>('/api/v1/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path, sign: opts.sign ?? true, lang: opts.langs ?? ['en', 'hi'] }),
    }),

  upload: (file: File, opts: { sign?: boolean; langs?: Lang[] } = {}) => {
    const form = new FormData()
    form.append('file', file)
    form.append('sign', String(opts.sign ?? true))
    form.append('lang', (opts.langs ?? ['en', 'hi']).join(','))
    return request<ScanSummary>('/api/v1/upload', { method: 'POST', body: form })
  },

  report: (scanId: string) => request<Report>(`/api/v1/report/${scanId}`),
}

export async function chainBlocks(): Promise<ChainBlock[]> {
  const res = await api.chain()
  return res.blocks ?? []
}
