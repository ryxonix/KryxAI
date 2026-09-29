import { useT } from '../i18n'
import type { MailSession } from '../lib/api'

function ratingColor(rating?: string): string {
  if (rating === 'strong' || rating === 'recommended') return '#3f6f4f'
  if (rating === 'acceptable') return '#b45309'
  if (rating === 'weak' || rating === 'broken') return '#DC2626'
  return '#71717A'
}

function starttlsState(t: (k: string) => string, s: MailSession['starttls']): { text: string; color: string } {
  if (s.signatures?.length) return { text: t('suppressed'), color: '#DC2626' }
  if (s.state === 'refused' || s.downgrade) return { text: t('refused'), color: '#DC2626' }
  if (s.tls_established) return { text: t('upgraded'), color: '#3f6f4f' }
  if (s.advertised && !s.upgrade_attempted) return { text: t('not offered'), color: '#b45309' }
  if (!s.advertised) return { text: t('not offered'), color: '#DC2626' }
  return { text: s.state || '—', color: '#b45309' }
}

/** One mail conversation from the capture. */
export function SessionCard({ session, onOpen }: { session: MailSession; onOpen?: (id: string) => void }) {
  const t = useT()
  const st = starttlsState(t, session.starttls)
  const tls = session.tls
  const r = session.reassembly

  return (
    <article className="session-card rounded-xl border border-[#E4E4E7] bg-white p-4 shadow-sm">
      <header className="flex flex-wrap items-baseline justify-between gap-2">
        <div className="flex min-w-0 items-baseline gap-2">
          <span className="font-mono text-[13px] font-semibold text-zinc-900">
            {session.endpoint}
          </span>
          <span className="rounded-full bg-[#F1EEE9] px-2 py-0.5 text-[11px] font-medium text-zinc-700">
            {session.protocol}
          </span>
          <span className="font-mono text-[11px] text-zinc-400">{session.session_id}</span>
        </div>
        <span className="text-[12px] font-semibold" style={{ color: st.color }}>
          STARTTLS: {st.text}
        </span>
      </header>

      {session.starttls.signatures?.length > 0 && (
        <ul className="mt-2 flex flex-wrap gap-1.5">
          {session.starttls.signatures.map((sig) => (
            <li
              key={sig}
              className="rounded bg-[#FCEEE7] px-1.5 py-0.5 font-mono text-[10.5px] text-[#C2410C]"
            >
              {sig}
            </li>
          ))}
        </ul>
      )}

      {session.starttls.obfuscated_tokens?.length ? (
        <p className="mt-2 font-mono text-[11.5px] text-zinc-500">
          {t('Obfuscated')}: {session.starttls.obfuscated_tokens.join(', ')}
        </p>
      ) : null}

      <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-2 sm:grid-cols-4">
        <div>
          <dt className="text-[10.5px] uppercase tracking-wider text-zinc-400">{t('TLS')}</dt>
          <dd className="font-mono text-[12.5px] text-zinc-800">{tls?.version ?? t('no TLS')}</dd>
        </div>
        <div>
          <dt className="text-[10.5px] uppercase tracking-wider text-zinc-400">{t('Cipher')}</dt>
          <dd className="truncate font-mono text-[12.5px]" style={{ color: ratingColor(tls?.cipher_rating) }}>
            {tls?.cipher_suite ?? '—'}
          </dd>
        </div>
        <div>
          <dt className="text-[10.5px] uppercase tracking-wider text-zinc-400">{t('Group')}</dt>
          <dd className="truncate font-mono text-[12.5px]" style={{ color: ratingColor(tls?.group_rating) }}>
            {tls?.key_exchange_group ?? '—'}
          </dd>
        </div>
        <div>
          <dt className="text-[10.5px] uppercase tracking-wider text-zinc-400">{t('SNI')}</dt>
          <dd className="truncate font-mono text-[12.5px] text-zinc-800">{tls?.sni ?? '—'}</dd>
        </div>
      </dl>

      {/* Certificate visibility must never be implied when the chain is hidden. */}
      {tls && !tls.certificate_visible && (
        <p className="mt-3 rounded bg-[#F1EEE9] px-2 py-1.5 text-[11.5px] leading-relaxed text-zinc-600">
          {t('Certificate')} — {t('Not assessed')} ({tls.version ?? 'TLS 1.3'}).{' '}
          {t('A visibility limit, not a passing result.')}
        </p>
      )}

      {tls?.not_assessed?.length ? (
        <p className="mt-2 text-[11.5px] text-zinc-500">
          {t('Not assessed')}: {tls.not_assessed.join(', ')}
        </p>
      ) : null}

      <footer className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-[#F1EEE9] pt-2.5 text-[11.5px] text-zinc-500">
        <span className="font-mono">
          {t('Bytes')}: {session.bytes.client}↑ / {session.bytes.server}↓
        </span>
        <span className={r.complete ? 'text-[#3f6f4f]' : 'text-[#C2410C]'}>
          {t('Reassembly')}: {r.complete ? t('Complete') : t('Incomplete')}
          {!r.complete && (r.client_gaps.length || r.server_gaps.length) && (
            <span className="ml-1 font-mono">
              ({r.client_gaps.length + r.server_gaps.length} gap(s))
            </span>
          )}
        </span>
        {onOpen && (
          <button onClick={() => onOpen(session.session_id)} className="underline underline-offset-2">
            {t('Evidence')}
          </button>
        )}
      </footer>
    </article>
  )
}
