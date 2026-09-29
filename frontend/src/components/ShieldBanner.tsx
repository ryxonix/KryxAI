import { useT } from '../i18n'
import type { Finding } from '../lib/api'

/**
 * Blocking alert for a critical finding.
 *
 * The reference application interrupted a live call when it suspected a cloned
 * voice. KryxAI is passive and never acts, so this is strictly informational:
 * it states the finding and the remediation and never implies that anything has
 * been blocked, contained or remediated.
 */
export function CriticalAlert({
  finding,
  onDismiss,
}: {
  finding: Finding
  onDismiss?: () => void
}) {
  const t = useT()
  if (!finding || finding.severity !== 'critical') return null

  return (
    <div
      className="critical-alert fixed inset-0 z-50 flex items-center justify-center bg-zinc-900/98 px-6 text-center"
      role="alert"
      aria-modal="true"
    >
      <div className="max-w-lg">
        <div className="mx-auto mb-5 flex h-14 w-14 items-center justify-center rounded-full bg-[#FCEEE7]">
          <svg
            viewBox="0 0 24 24"
            width="28"
            height="28"
            fill="none"
            stroke="#C2410C"
            strokeWidth="1.8"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="M12 3 2.5 8.5 12 18l9.5-4.5L12 3z" />
            <path d="M12 18v3M6 21h12" />
          </svg>
        </div>
        <div className="font-serif text-[22px] font-bold tracking-tight text-zinc-900 leading-tight">
          {finding.title}
        </div>
        <p className="mt-2 text-[14px] leading-relaxed text-zinc-600">{finding.detail}</p>

        {finding.remediation && (
          <p className="mt-3 text-[13px] leading-relaxed text-zinc-700">
            <span className="font-semibold">{t('Remediation')}: </span>
            {finding.remediation}
          </p>
        )}

        <div className="mt-6 flex flex-wrap justify-center gap-3">
          <button
            onClick={onDismiss}
            className="rounded-full border border-zinc-900 bg-zinc-900 px-6 py-2 text-[13.5px] font-semibold text-white transition-colors hover:bg-zinc-700"
          >
            {t('Dismiss')}
          </button>
        </div>

        <dl className="mt-6 flex flex-wrap items-center justify-center gap-x-2.5 gap-y-1 text-[12px] text-zinc-500">
          {finding.endpoint && (
            <div className="flex gap-1">
              <dt className="font-semibold text-zinc-700">{t('Endpoint')}</dt>
              <dd className="font-mono text-zinc-900">{finding.endpoint}</dd>
            </div>
          )}
          {finding.reference && (
            <div className="flex gap-1">
              <dt className="font-semibold text-zinc-700">{t('Reference')}</dt>
              <dd className="text-zinc-900">{finding.reference}</dd>
            </div>
          )}
          {typeof finding.weight === 'number' && (
            <div className="flex gap-1" title={t('Ordering heuristic, not a probability')}>
              <dt className="font-semibold text-zinc-700">{t('Detection weight')}</dt>
              <dd className="font-mono text-zinc-900">{finding.weight.toFixed(2)}</dd>
            </div>
          )}
        </dl>

        {/* Be explicit that nothing was acted on. */}
        <p className="mt-5 text-[11.5px] italic leading-relaxed text-zinc-400">
          {t('Observes an existing capture. It never probes, scans or modifies anything.')}
        </p>
      </div>
    </div>
  )
}

/** Non-blocking inline strip for high-severity findings. */
export function FindingStrip({ finding }: { finding: Finding }) {
  if (!finding || !['critical', 'high'].includes(finding.severity)) return null
  const color = finding.severity === 'critical' ? '#DC2626' : '#C2410C'
  return (
    <div
      className="risk-banner rounded-xl border px-4 py-3 text-[13.5px] leading-relaxed shadow-sm"
      style={{ borderColor: color, background: `${color}08` }}
      role="status"
    >
      <div className="flex flex-col gap-1 sm:flex-row sm:items-start sm:gap-3">
        <span
          aria-hidden="true"
          className="mt-1.5 h-2 w-2 shrink-0 rounded-full"
          style={{ background: color }}
        />
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <span className="font-medium text-zinc-900">{finding.title}</span>
          {finding.endpoint && (
            <span className="font-mono text-zinc-500">{finding.endpoint}</span>
          )}
          {finding.risk?.priority && (
            <span className="font-mono text-zinc-400">{finding.risk.priority}</span>
          )}
        </div>
      </div>
    </div>
  )
}
