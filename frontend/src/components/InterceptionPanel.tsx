import { useState } from 'react'
import { useT } from '../i18n'
import type { InterceptionEvidence, InterceptionSession, InterceptionVerdict } from '../lib/api'

/**
 * The one claim a live scanner cannot make.
 *
 * Every passive tool can report "this session was unencrypted". This panel is
 * about the stronger claim: the capability advertisement itself was rewritten,
 * so a client that believed no upgrade existed was misled. That is the
 * differentiator, so it is shown as a comparison against the token each
 * protocol defines, with the reasoning stated on the record.
 *
 * Two things it deliberately does not do: name a culprit, and imply anything was
 * blocked or remediated. The attribution limit is rendered inline rather than
 * hidden in a footnote, because a screenshot of this panel travels without it.
 */

const VERDICT_STYLE: Record<InterceptionVerdict, { ring: string; dot: string; label: string }> = {
  tampered_advertisement: { ring: 'border-[#DC2626]', dot: 'bg-[#DC2626]', label: 'text-[#B91C1C]' },
  unencrypted_but_unmodified: { ring: 'border-[#C2410C]', dot: 'bg-[#C2410C]', label: 'text-[#9A3412]' },
  no_evidence_of_interception: { ring: 'border-[#059669]', dot: 'bg-[#059669]', label: 'text-[#047857]' },
}

function SessionRow({ s }: { s: InterceptionSession }) {
  const t = useT()
  const [open, setOpen] = useState(false)
  const tampered = s.signatures.length > 0

  return (
    <li className="border-t border-zinc-200/70 first:border-t-0">
      <button
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        className="flex w-full items-center gap-3 py-3 text-left hover:bg-zinc-50/70"
      >
        <span
          aria-hidden="true"
          className={`h-2 w-2 shrink-0 rounded-full ${tampered ? 'bg-[#DC2626]' : 'bg-zinc-300'}`}
        />
        <span className="font-mono text-[12.5px] font-semibold text-zinc-900">{s.endpoint}</span>
        <span className="font-mono text-[11.5px] text-zinc-500">{s.protocol}:{s.port}</span>
        <span
          className={`ml-auto shrink-0 font-mono text-[11.5px] ${tampered ? 'text-[#B91C1C]' : 'text-zinc-500'}`}
        >
          {tampered ? s.signatures.join(' + ') : s.state}
        </span>
        <svg
          viewBox="0 0 24 24"
          width="14"
          height="14"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          aria-hidden="true"
          className={`shrink-0 text-zinc-400 transition-transform ${open ? 'rotate-180' : ''}`}
        >
          <path d="m6 9 6 6 6-6" />
        </svg>
      </button>

      {open && (
        <div className="pb-4 pl-5 pr-1">
          {tampered ? (
            <div className="rounded-lg border border-[#F5D0D0] bg-[#FEF6F6] p-3">
              <div className="flex flex-wrap items-center gap-2 font-mono text-[12px]">
                <span className="text-zinc-500">{t('Expected')}</span>
                <span className="rounded bg-white px-1.5 py-0.5 font-semibold text-zinc-900 ring-1 ring-zinc-200">
                  {s.expected_token}
                </span>
                <span aria-hidden="true" className="text-zinc-400">→</span>
                <span className="text-zinc-500">{t('observed in the greeting')}</span>
                {(s.observed_tokens ?? []).map((tok, i) => (
                  <span
                    key={`${tok}-${i}`}
                    className="rounded bg-white px-1.5 py-0.5 font-semibold text-[#B91C1C] ring-1 ring-[#F0B4B4]"
                  >
                    {tok}
                  </span>
                ))}
              </div>
              {s.signature_details.map(d => (
                <div key={d.code} className="mt-3">
                  <div className="text-[13px] font-semibold text-zinc-900">{d.title}</div>
                  <p className="mt-1 text-[12.5px] leading-relaxed text-zinc-600">{d.mechanism}</p>
                  <p className="mt-1 text-[12.5px] leading-relaxed text-zinc-700">{d.why_it_matters}</p>
                  {d.reference && (
                    <div className="mt-1.5 font-mono text-[11px] text-zinc-400">{d.reference}</div>
                  )}
                </div>
              ))}
              {s.remediation && (
                <p className="mt-3 border-t border-[#F0B4B4] pt-2 text-[12.5px] leading-relaxed text-zinc-700">
                  <span className="font-semibold">{t('Remediation')}: </span>
                  {s.remediation}
                </p>
              )}
            </div>
          ) : (
            <div className="rounded-lg border border-zinc-200 bg-zinc-50 p-3 text-[12.5px] leading-relaxed text-zinc-600">
              {s.tls_established
                ? t(
                    'The upgrade was offered and completed. The greeting matched the token this protocol defines, and every byte after the handshake was encrypted.',
                  )
                : t(
                    'This session stayed in cleartext, but the advertisement matched the token this protocol defines. That is an unconfigured listener, not a rewritten greeting.',
                  )}
            </div>
          )}

          <dl className="mt-2 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[11px] text-zinc-400">
            <div className="flex gap-1">
              <dt>{t('state')}</dt>
              <dd className="text-zinc-600">{s.state}</dd>
            </div>
            <div className="flex gap-1">
              <dt>{t('encrypted')}</dt>
              <dd className="text-zinc-600">{s.encrypted_bytes} B</dd>
            </div>
            <div className="flex gap-1" title={t('Confidence in the structural signature, not a probability')}>
              <dt>{t('confidence')}</dt>
              <dd className="text-zinc-600">{s.confidence.toFixed(2)}</dd>
            </div>
            {s.anomalies.map(code => (
              <div key={code} className="flex gap-1">
                <dt>{t('anomaly')}</dt>
                <dd className="text-zinc-600">{code}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}
    </li>
  )
}

export function InterceptionPanel({ evidence }: { evidence?: InterceptionEvidence }) {
  const t = useT()
  const [whyOpen, setWhyOpen] = useState(false)
  // Absent means a report written before this field existed. Rendering an empty
  // green panel would read as "no interception found", which is a claim, not a
  // gap. Say the data is missing instead.
  if (!evidence) return null

  const style = VERDICT_STYLE[evidence.verdict] ?? VERDICT_STYLE.no_evidence_of_interception
  const tampered = evidence.sessions.filter(s => s.signatures.length > 0)

  return (
    <section className="card border border-zinc-200 shadow-sm" aria-labelledby="interception-heading">
      <div className="border-b border-zinc-200/70 px-5 py-4">
        <div className="flex flex-wrap items-center gap-2">
          <h2
            id="interception-heading"
            className="font-serif text-[15px] font-bold tracking-tight text-zinc-900"
          >
            {t('Downgrade & interception evidence')}
          </h2>
          <span
            className={`rounded-full border px-2 py-0.5 font-mono text-[10.5px] font-semibold uppercase tracking-wide ${style.ring} ${style.label}`}
          >
            {evidence.verdict.replace(/_/g, ' ')}
          </span>
          <span className="ml-auto font-mono text-[11px] text-zinc-400">{evidence.reference}</span>
        </div>
        <p className="mt-2 text-[13.5px] leading-relaxed text-zinc-700">{evidence.headline}</p>
      </div>

      <div className="grid grid-cols-2 gap-px border-b border-zinc-200/70 bg-zinc-200/70 sm:grid-cols-4">
        {[
          [t('Assessed'), evidence.sessions_assessed],
          [t('Advertisement altered'), evidence.sessions_tampered],
          [t('Upgraded'), evidence.sessions_upgraded],
          [t('Cleartext'), evidence.sessions_cleartext],
        ].map(([label, n]) => (
          <div key={String(label)} className="bg-white px-5 py-3">
            <div className="font-mono text-[19px] font-bold leading-none text-zinc-900">{n}</div>
            <div className="mt-1 text-[11.5px] leading-tight text-zinc-500">{label}</div>
          </div>
        ))}
      </div>

      {evidence.sessions_assessed > 0 && (
        <ul className="px-5 py-1">
          {evidence.sessions.map(s => (
            <SessionRow key={s.session_id} s={s} />
          ))}
        </ul>
      )}

      <div className="border-t border-zinc-200/70 bg-zinc-50/60 px-5 py-3">
        <p className="text-[12px] leading-relaxed text-zinc-600">
          <span aria-hidden="true" className={`mr-1.5 inline-block h-1.5 w-1.5 rounded-full align-middle ${style.dot}`} />
          {evidence.attribution_limit}
        </p>
        <button
          onClick={() => setWhyOpen(!whyOpen)}
          aria-expanded={whyOpen}
          className="mt-2 text-[12px] font-semibold text-zinc-700 underline decoration-zinc-300 underline-offset-2 hover:decoration-zinc-500"
        >
          {t('Why a live scanner cannot make this claim')}
        </button>
        {whyOpen && (
          <p className="mt-2 text-[12.5px] leading-relaxed text-zinc-600">{evidence.why_passive}</p>
        )}
      </div>

      {tampered.length > 0 && (
        <p className="border-t border-zinc-200/70 px-5 py-2.5 text-[11.5px] italic text-zinc-400">
          {t('Observes an existing capture. It never probes, scans or modifies anything.')}
        </p>
      )}
    </section>
  )
}
