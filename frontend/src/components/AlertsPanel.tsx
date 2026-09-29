/**
 * Did the operator actually get told?
 *
 * This panel exists to close a loop that would otherwise be open. A scan can
 * find a critical finding and notify nobody, because no channel was configured
 * or because the webhook was down. Both are recorded in `report.alerts`. But a
 * record nobody reads is not an answer, and the failure mode is specific: an
 * operator glances at the dashboard, sees a critical finding, and concludes
 * someone was paged. Nobody was. So the *failure* state is the loud one here,
 * deliberately louder than the success state.
 *
 * Two things it does not do. It does not render at all when `report.alerts` is
 * absent: a report from a build that predates alerting is a gap, not a quiet
 * success, and a green "notified" panel drawn over missing data is the exact
 * lie this panel exists to prevent. And it does not treat a 2xx as proof of
 * delivery - that is a hand-off, not a read receipt, and the wording says so.
 *
 * Delivery is deliberately excluded from the evidence chain. An alert is an
 * operational side effect of a scan, not an observation about the capture, so
 * it must never be able to change what the report attests to.
 */

import { useT } from '../i18n'
import type { AlertDelivery, AlertReport } from '../lib/api'

const SENT = {
  ring: '#3f6f4f',
  label: 'text-[#2f5a3e]',
  text: 'text-zinc-700',
} as const

const FAILED = {
  ring: '#DC2626',
  label: 'text-[#B91C1C]',
  text: 'text-[#7F1D1D]',
} as const

const IDLE = {
  ring: '#E4E4E7',
  label: 'text-zinc-500',
  text: 'text-zinc-600',
} as const

function DeliveryRow({ d }: { d: AlertDelivery }) {
  const t = useT()
  const ok = d.status === 'sent'
  return (
    <li className="flex flex-wrap items-baseline gap-x-2.5 gap-y-1 border-b border-[#F1F1F3] py-2.5 last:border-b-0">
      <span
        aria-hidden="true"
        className="h-1.5 w-1.5 shrink-0 self-center rounded-full"
        style={{ background: ok ? SENT.ring : FAILED.ring }}
      />
      <span className="font-mono text-[12.5px] font-semibold text-zinc-900">{d.channel}</span>
      <span className="font-mono text-[11.5px] text-zinc-400">{d.target}</span>
      <span
        className={`font-mono text-[10.5px] font-semibold uppercase tracking-wide ${
          ok ? SENT.label : FAILED.label
        }`}
      >
        {ok ? t('handed off') : t('failed')}
      </span>
      {d.attempts > 1 && (
        <span className="font-mono text-[11px] text-zinc-400">
          {t('{n} attempt(s)', { n: d.attempts })}
        </span>
      )}
      {d.error && <span className="w-full font-mono text-[11px] leading-relaxed text-[#9A3412]">{d.error}</span>}
    </li>
  )
}

export function AlertsPanel({ alerts }: { alerts?: AlertReport }) {
  const t = useT()
  // Absent means a report written before this build had alerting. Say nothing
  // rather than draw a panel: silence is honest here, a "notified" badge is not.
  if (!alerts) return null

  const failed = alerts.failures.length > 0
  // A failed delivery is the loudest state; an all-clear is quiet. Neutral in
  // between, for "nothing needed sending", keeps attention on the one case
  // that matters - the scan where somebody was not told.
  const tone = failed ? FAILED : alerts.triggered ? SENT : IDLE

  const headline = failed
    ? t('The operator was not notified')
    : alerts.triggered
      ? t('Operator notified')
      : t('No notification sent')

  const explanation = failed
    ? t(
        'At least one channel did not accept the notification. The findings are still in the report, but they were not announced, and this scan should not be relied on as having raised anyone.',
      )
    : alerts.triggered
      ? t(
          'The channels below accepted the notification. That is a hand-off, not a read receipt - nothing here proves a person saw it.',
        )
      : (alerts.skipped_reason ?? t('No alert channel is configured.'))

  return (
    <section
      className="rounded-xl border bg-white p-5"
      style={{ borderColor: tone.ring }}
      aria-labelledby="alerts-heading"
    >
      <div className="mb-1 flex flex-wrap items-center gap-2">
        <h2 id="alerts-heading" className="font-serif text-[15px] font-semibold text-zinc-900">
          {t('Notification')}
        </h2>
        <span
          className={`rounded-full border px-2 py-0.5 font-mono text-[10.5px] font-semibold uppercase tracking-wide ${tone.label}`}
          style={{ borderColor: tone.ring }}
        >
          {headline}
        </span>
        {alerts.enabled && (
          <span
            className="rounded-full border border-[#E4E4E7] px-2 py-0.5 font-mono text-[10.5px] text-zinc-500"
            title={t('Findings below this severity never notify')}
          >
            {t('at or above')} {alerts.min_severity}
          </span>
        )}
        <span className="ml-auto font-mono text-[11px] text-zinc-500">
          {alerts.triggered
            ? t('{n} channel(s) attempted', { n: alerts.deliveries.length })
            : t('no channel attempted')}
        </span>
      </div>

      <p className={`text-[12.5px] leading-relaxed ${tone.text}`}>{explanation}</p>

      {alerts.deliveries.length > 0 && (
        <ul className="mt-3">
          {alerts.deliveries.map(d => (
            <DeliveryRow key={`${d.channel}-${d.target}`} d={d} />
          ))}
        </ul>
      )}

      {!alerts.triggered && alerts.channels_configured.length > 0 && (
        <p className="mt-3 font-mono text-[11.5px] text-zinc-500">
          {t('configured')}: {alerts.channels_configured.join(', ')}
        </p>
      )}

      <p className="mt-3 border-t border-[#F1F1F3] pt-2 text-[11px] leading-relaxed text-zinc-500">
        {t(
          'Alerting is the only outbound call KryxAI makes; it is passive otherwise. Delivery is best-effort, never affects the scan result, and is not part of the evidence chain.',
        )}
      </p>
    </section>
  )
}
