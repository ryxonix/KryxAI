import { useMemo, useState } from 'react'
import { PageHeader, Divider } from '../components/ui'
import { XaiBars, useRiskFactors, bandColor } from '../components/RiskGauge'
import { useT, useI18n, localized } from '../i18n'
import type { Finding, Report } from '../lib/api'

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const

function severityColor(sev: string): string {
  return bandColor(sev === 'critical' ? 'critical' : sev === 'high' ? 'high' : sev === 'medium' ? 'medium' : 'A')
}

function FindingRow({ finding, lang }: { finding: Finding; lang: 'en' | 'hi' }) {
  const t = useT()
  const [open, setOpen] = useState(false)
  const factors = useRiskFactors(finding)

  return (
    <li className="rounded-xl border border-[#E4E4E7] bg-white">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-start gap-3 px-4 py-3 text-left"
        aria-expanded={open}
      >
        <span
          aria-hidden="true"
          className="mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full"
          style={{ background: severityColor(finding.severity) }}
        />
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-baseline gap-x-2">
            <span className="text-[13.5px] font-medium text-zinc-900">{localized(finding, lang)}</span>
            <span
              className="rounded px-1.5 py-0.5 text-[10.5px] font-semibold uppercase"
              style={{ background: `${severityColor(finding.severity)}14`, color: severityColor(finding.severity) }}
            >
              {t(`sev.${finding.severity}`)}
            </span>
            {finding.risk?.priority && (
              <span className="font-mono text-[10.5px] text-zinc-400">{finding.risk.priority}</span>
            )}
            {finding.risk?.model === 'onnx' && (
              <span
                className="rounded bg-[#F1EEE9] px-1.5 py-0.5 text-[10px] text-zinc-500"
                title={
                  finding.risk?.rule_score !== undefined &&
                  finding.risk?.model_score !== undefined &&
                  finding.risk?.model_score !== null
                    ? `rules ${finding.risk.rule_score} · model ${finding.risk.model_score.toFixed(2)} · fused ${finding.risk.total}`
                    : 'Model score unavailable'
                }
              >
                ONNX
              </span>
            )}
          </span>
          <span className="mt-0.5 flex flex-wrap gap-x-3 font-mono text-[11px] text-zinc-400">
            {finding.endpoint && <span>{finding.endpoint}</span>}
            {finding.session_id && <span>{finding.session_id}</span>}
            <span className="font-sans">{finding.code}</span>
          </span>
        </span>
      </button>

      {open && (
        <div className="border-t border-[#F1EEE9] px-4 py-3">
          <p className="text-[12.5px] leading-relaxed text-zinc-700">{finding.detail}</p>

          {finding.remediation && (
            <p className="mt-2 text-[12.5px] leading-relaxed text-zinc-700">
              <span className="font-semibold">{t('Remediation')}: </span>
              {finding.remediation}
            </p>
          )}

          <div className="mt-3 grid gap-4 sm:grid-cols-2">
            <div>
              <h3 className="mb-1.5 text-[10.5px] uppercase tracking-wider text-zinc-400">
                {t('Risk breakdown')}
              </h3>
              <XaiBars factors={factors} emptyLabel={t('No further detail available.')} />
            </div>
            <div>
              <h3 className="mb-1.5 text-[10.5px] uppercase tracking-wider text-zinc-400">
                {t('Evidence')}
              </h3>
              {finding.evidence && Object.keys(finding.evidence).length > 0 ? (
                <dl className="space-y-1">
                  {Object.entries(finding.evidence).map(([k, v]) => (
                    <div key={k} className="flex gap-2 text-[11.5px]">
                      <dt className="shrink-0 text-zinc-500">{k}</dt>
                      <dd className="min-w-0 break-words font-mono text-zinc-800">
                        {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                      </dd>
                    </div>
                  ))}
                </dl>
              ) : (
                <p className="text-[11.5px] italic text-zinc-400">{t('No further detail available.')}</p>
              )}

              <dl className="mt-2 space-y-1 text-[11.5px]">
                {typeof finding.weight === 'number' && (
                  <div className="flex gap-2" title={t('Ordering heuristic, not a probability')}>
                    <dt className="text-zinc-500">{t('Detection weight')}</dt>
                    <dd className="font-mono text-zinc-800">{finding.weight.toFixed(2)}</dd>
                  </div>
                )}
                {finding.reference && (
                  <div className="flex gap-2">
                    <dt className="text-zinc-500">{t('Reference')}</dt>
                    <dd className="text-zinc-800">{finding.reference}</dd>
                  </div>
                )}
                {finding.deliverable && (
                  <div className="flex gap-2">
                    <dt className="text-zinc-500">D</dt>
                    <dd className="text-zinc-800">{finding.deliverable}</dd>
                  </div>
                )}
              </dl>
            </div>
          </div>
        </div>
      )}
    </li>
  )
}

export default function Findings({ report }: { report: Report | null }) {
  const t = useT()
  const { lang } = useI18n()
  const [severity, setSeverity] = useState<string>('all')
  const [query, setQuery] = useState('')

  const counts = report?.counts.by_severity ?? {}

  const filtered = useMemo(() => {
    if (!report) return []
    const q = query.trim().toLowerCase()
    return report.findings
      .filter((f) => (severity === 'all' ? true : f.severity === severity))
      .filter((f) =>
        !q
          ? true
          : [f.code, f.title, f.title_hi, f.endpoint, f.detail]
              .filter(Boolean)
              .some((s) => String(s).toLowerCase().includes(q)),
      )
      .sort(
        (a, b) =>
          SEVERITY_ORDER.indexOf(a.severity as any) - SEVERITY_ORDER.indexOf(b.severity as any) ||
          (b.risk?.total ?? 0) - (a.risk?.total ?? 0),
      )
  }, [report, severity, query])

  return (
    <div>
      <PageHeader
        title={t('Findings')}
        meta={report ? t('{n} finding(s)', { n: report.findings.length }) : undefined}
      />
      <Divider />

      {!report ? (
        <p className="text-[13px] text-zinc-500">{t('No capture analysed yet')}</p>
      ) : (
        <>
          <div className="mb-4 flex flex-wrap items-center gap-2">
            {['all', ...SEVERITY_ORDER].map((s) => {
              const active = severity === s
              const n = s === 'all' ? report.findings.length : (counts[s] ?? 0)
              return (
                <button
                  key={s}
                  onClick={() => setSeverity(s)}
                  className={`rounded-full px-3 py-1 text-[12px] font-medium transition-colors ${
                    active
                      ? 'bg-zinc-900 text-white'
                      : 'border border-[#E4E4E7] bg-white text-zinc-700 hover:bg-[#F1EEE9]'
                  }`}
                >
                  {s === 'all' ? t('Findings') : t(`sev.${s}`)} <span className="font-mono">{n}</span>
                </button>
              )
            })}
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={t('Filter')}
              aria-label={t('Filter')}
              className="ml-auto rounded-full border border-[#E4E4E7] px-3 py-1 text-[12px] outline-none focus:border-zinc-400"
            />
          </div>

          {filtered.length === 0 ? (
            <p className="text-[13px] italic text-zinc-500">{t('No findings in this capture.')}</p>
          ) : (
            <ul className="space-y-2">
              {filtered.map((f) => (
                <FindingRow key={f.finding_id} finding={f} lang={lang} />
              ))}
            </ul>
          )}
        </>
      )}
    </div>
  )
}
