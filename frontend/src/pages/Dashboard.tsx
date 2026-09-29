import { useEffect, useMemo, useState } from 'react'
import { PageHeader, Divider, apiBase } from '../components/ui'
import { RiskGauge, XaiBars, dimensionFactors } from '../components/RiskGauge'
import { Radar, type RadarAxis } from '../components/Radar'
import { FindingStrip } from '../components/ShieldBanner'
import { CompliancePanel } from '../components/CompliancePanel'
import { CoveragePanel } from '../components/CoveragePanel'
import { InterceptionPanel } from '../components/InterceptionPanel'
import { AlertsPanel } from '../components/AlertsPanel'
import { SessionCard } from '../components/SessionCard'
import { useT, useI18n, localized } from '../i18n'
import { api, type Capabilities, type Health, type Report } from '../lib/api'

function severityColor(sev: string): string {
  if (sev === 'critical') return '#DC2626'
  if (sev === 'high') return '#C2410C'
  if (sev === 'medium') return '#b45309'
  if (sev === 'low') return '#3f6f4f'
  return '#71717A'
}

export default function Dashboard({
  report,
  onNavigate,
}: {
  report: Report | null
  onNavigate?: (id: 'dashboard' | 'scan' | 'findings' | 'reports') => void
}) {
  const t = useT()
  const { lang } = useI18n()
  const [health, setHealth] = useState<Health | null>(null)
  const [caps, setCaps] = useState<Capabilities | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api.health().then(setHealth).catch((e) => setError(e.message))
    api.capabilities().then(setCaps).catch(() => undefined)
  }, [])

  const axes: RadarAxis[] = useMemo(() => {
    if (!report) return []
    return Object.entries(report.posture.dimensions).map(([key, value]) => ({
      key,
      label: t(key),
      value,
    }))
  }, [report, t])

  if (!report) {
    return (
      <div>
        <PageHeader
          title={t('Overview')}
          meta={t('Passive mail-security forensics')}
        />
        <Divider />
        <div className="rounded-xl border border-dashed border-[#E4E4E7] bg-white p-10 text-center">
          <p className="text-[14px] text-zinc-600">{t('No capture analysed yet')}</p>
          <p className="mt-1 text-[12.5px] text-zinc-500">
            {t('Upload a capture to see posture, findings and the evidence chain.')}
          </p>
          <button
            className="mt-4 rounded-full border border-zinc-900 bg-zinc-900 px-5 py-2 text-[13px] font-semibold text-white transition-colors hover:bg-zinc-700"
            onClick={() => onNavigate?.('scan')}
          >
            {t('New scan')}
          </button>
        </div>
        {error && <p className="mt-4 text-[12.5px] text-[#C2410C]">{t('Error: {e}', { e: error })}</p>}
      </div>
    )
  }

  const p = report.posture
  const counts = report.counts
  const ev = report.evidence
  const top = [...report.findings]
    .filter((f) => f.severity === 'critical' || f.severity === 'high')
    .slice(0, 3)

  return (
    <div>
      <PageHeader
        title={t('Overview')}
        meta={`${report.source.path} · SHA-256 ${report.source.sha256.slice(0, 16)}…`}
      />
      <Divider />

      {/* Chain status first: it qualifies everything else on the page. */}
      <div
        className="mb-5 rounded-xl border px-4 py-3 text-[12.5px] leading-relaxed"
        style={{
          borderColor: ev.chain_state === 'anchored' ? '#3f6f4f' : '#b45309',
          background: ev.chain_state === 'anchored' ? '#3f6f4f08' : '#b4530908',
        }}
      >
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <span className="font-semibold text-zinc-900">
            {t(`chain.${ev.chain_state}`) ?? t('Not anchored')}
          </span>
          <span className="font-mono text-zinc-500">
            {ev.chain_id} · {t('Block')} {ev.block_index ?? '—'}
          </span>
          {ev.block_hash && (
            <span className="font-mono text-zinc-400">{ev.block_hash.slice(0, 16)}…</span>
          )}
        </div>
        {ev.chain_state !== 'anchored' && (
          <p className="mt-1 text-zinc-600">
            {t('This is not a compliance determination.')}
          </p>
        )}
      </div>

      {top.map((f) => (
        <FindingStrip key={f.finding_id} finding={f} />
      ))}
      {top.length > 0 && <div className="h-4" />}

      {/* Directly after the strips it qualifies: a critical finding nobody was
          told about is a different situation from one that was announced. */}
      {report.alerts && (
        <div className="mb-5">
          <AlertsPanel alerts={report.alerts} />
        </div>
      )}

      <div className="grid gap-6 md:grid-cols-2">
        <section className="rounded-xl border border-[#E4E4E7] bg-white p-5">
          <h2 className="mb-3 font-serif text-[15px] font-semibold text-zinc-900">
            {t('Security posture')}
          </h2>
          <div className="flex flex-col items-center gap-4 sm:flex-row sm:items-start">
            <RiskGauge score={p.score} grade={p.grade} label={p.label} />
            <dl className="grid flex-1 grid-cols-2 gap-x-4 gap-y-2 text-[12.5px]">
              <div>
                <dt className="text-[10.5px] uppercase tracking-wider text-zinc-400">
                  {t('Sessions measured')}
                </dt>
                <dd className="font-mono text-zinc-800">
                  {p.sessions_measured} ({p.mail_sessions_measured} {t('mail')})
                </dd>
              </div>
              <div>
                <dt className="text-[10.5px] uppercase tracking-wider text-zinc-400">{t('TLS')}</dt>
                <dd className="font-mono text-zinc-800">
                  {counts.tls_upgraded}/{counts.mail_sessions}
                </dd>
              </div>
              <div>
                <dt className="text-[10.5px] uppercase tracking-wider text-zinc-400">{t('Findings')}</dt>
                <dd className="font-mono text-zinc-800">{counts.findings}</dd>
              </div>
              <div>
                <dt className="text-[10.5px] uppercase tracking-wider text-zinc-400">
                  {t('Scan time')}
                </dt>
                <dd className="font-mono text-zinc-800">{report.scan_seconds.toFixed(2)}s</dd>
              </div>
            </dl>
          </div>

          {p.not_assessed.length > 0 && (
            <p className="mt-3 rounded bg-[#F1EEE9] px-2.5 py-1.5 text-[11.5px] leading-relaxed text-zinc-600">
              {t('Not assessed')}: {p.not_assessed.join(', ')}. {t('A visibility limit, not a passing result.')}
            </p>
          )}

          <div className="mt-4">
            <h3 className="mb-2 text-[11px] uppercase tracking-wider text-zinc-400">
              {t('Scoring dimensions')}
            </h3>
            <XaiBars factors={dimensionFactors(p.dimensions, t)} />
            {p.dimension_explanation && (
              <ul className="mt-2.5 space-y-1">
                {Object.entries(p.dimension_explanation).map(([key, meta]) => (
                  <li key={key} className="text-[11px] leading-relaxed text-zinc-500">
                    <span className="font-semibold text-zinc-600">{t(key)}:</span> {meta.rationale}
                    <span className="ml-1 font-mono text-[10px] text-zinc-400">
                      ({meta.points.toFixed(1)} pts)
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </section>

        <section className="rounded-xl border border-[#E4E4E7] bg-white p-5">
          <h2 className="mb-3 font-serif text-[15px] font-semibold text-zinc-900">
            {t('Scoring dimensions')}
          </h2>
          <Radar axes={axes} notAssessed={p.not_assessed} />
        </section>
      </div>

      <div className="mt-6 grid gap-6 md:grid-cols-2">
        <section className="rounded-xl border border-[#E4E4E7] bg-white p-5">
          <h2 className="mb-3 font-serif text-[15px] font-semibold text-zinc-900">{t('Findings')}</h2>
          {report.findings.length === 0 ? (
            <p className="text-[12.5px] italic text-zinc-500">{t('No findings in this capture.')}</p>
          ) : (
            <ul className="space-y-2">
              {[...report.findings]
                .sort(
                  (a, b) =>
                    (b.risk?.total ?? 0) - (a.risk?.total ?? 0),
                )
                .slice(0, 8)
                .map((f) => (
                  <li key={f.finding_id} className="flex items-start gap-2.5">
                    <span
                      aria-hidden="true"
                      className="mt-1.5 h-2 w-2 shrink-0 rounded-full"
                      style={{ background: severityColor(f.severity) }}
                    />
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-baseline gap-x-2">
                        <span className="text-[12.5px] text-zinc-800">
                          {localized(f, lang)}
                        </span>
                        {f.risk?.priority && (
                          <span className="font-mono text-[10.5px] text-zinc-400">
                            {f.risk.priority}
                          </span>
                        )}
                      </div>
                      {f.endpoint && (
                        <span className="font-mono text-[11px] text-zinc-400">{f.endpoint}</span>
                      )}
                    </div>
                  </li>
                ))}
            </ul>
          )}
          {report.findings.length > 8 && (
            <button className="mt-3 text-[12.5px] underline underline-offset-2" onClick={() => onNavigate?.('findings')}>
              {t('{n} finding(s)', { n: report.findings.length })}
            </button>
          )}
        </section>

        <section className="rounded-xl border border-[#E4E4E7] bg-white p-5">
          <h2 className="mb-3 font-serif text-[15px] font-semibold text-zinc-900">
            {t('Limitations')}
          </h2>
          <ul className="space-y-1.5">
            {report.limitations.map((l, i) => (
              <li key={i} className="flex items-start gap-2 text-[12.5px] leading-relaxed text-zinc-600">
                <span className="mt-px shrink-0 text-zinc-400">▸</span>
                <span>{l}</span>
              </li>
            ))}
          </ul>
          {caps?.known_limitations?.length ? (
            <>
              <h3 className="mb-1.5 mt-4 text-[11px] uppercase tracking-wider text-zinc-400">
                {t('What this build cannot see')}
              </h3>
              <ul className="space-y-1.5">
                {caps.known_limitations.map((l, i) => (
                  <li key={i} className="flex items-start gap-2 text-[12.5px] leading-relaxed text-zinc-600">
                    <span className="mt-px shrink-0 text-zinc-400">▸</span>
                    <span>{l}</span>
                  </li>
                ))}
              </ul>
            </>
          ) : null}
        </section>
      </div>

      {report.interception && (
        <div className="mt-6">
          <InterceptionPanel evidence={report.interception} />
        </div>
      )}

      {report.coverage && (
        <div className="mt-6">
          <CoveragePanel coverage={report.coverage} />
        </div>
      )}

      {report.compliance && (
        <div className="mt-6">
          <CompliancePanel compliance={report.compliance} />
        </div>
      )}

      {report.model && report.model.used && report.model.sessions_with_clamped_features !== undefined &&
        report.model.sessions_with_clamped_features > 0 && (
          <div className="mt-6 rounded-xl border border-[#E4E4E7] bg-white p-5">
            <h2 className="mb-2 font-serif text-[15px] font-semibold text-zinc-900">
              {t('Model scoring clamp')}
            </h2>
            <p className="text-[12.5px] leading-relaxed text-zinc-600">
              {t('{n} session(s) had inputs outside the range the model was trained on and were clamped before scoring.', {
                n: report.model.sessions_with_clamped_features,
              })}
            </p>
            {report.model.clamped_features && report.model.clamped_features.length > 0 && (
              <p className="mt-1 text-[11.5px]">
                <span className="font-mono text-zinc-500">{report.model.clamped_features.slice(0, 6).join(', ')}</span>
                {report.model.clamped_features.length > 6 && (
                  <span className="text-zinc-400"> +{report.model.clamped_features.length - 6} more</span>
                )}
              </p>
            )}
            {report.model.constant_training_features &&
              report.model.constant_training_features.length > 0 && (
                <p className="mt-2 text-[11.5px] text-zinc-500">
                  {t('Constant in training:')}{' '}
                  <span className="font-mono">
                    {report.model.constant_training_features.slice(0, 4).join(', ')}
                    {report.model.constant_training_features.length > 4 && ' …'}
                  </span>
                </p>
              )}
          </div>
        )}

      <div className="mt-6">
        <h2 className="mb-3 font-serif text-[15px] font-semibold text-zinc-900">{t('Captures')}</h2>
        <div className="space-y-3">
          {report.sessions.map((s) => (
            <SessionCard key={s.session_id} session={s} />
          ))}
        </div>
      </div>

      <footer className="mt-8 border-t border-[#E4E4E7] pt-4 text-[11.5px] leading-relaxed text-zinc-500">
        {t('A clean report is not proof of a compliant control; it reflects only the traffic present in the supplied capture.')}
        <span className="ml-1 font-mono text-zinc-400">
          {health?.version ? `v${health.version}` : ''} {apiBase() || ''}
        </span>
      </footer>
    </div>
  )
}
