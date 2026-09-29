import { useEffect, useState } from 'react'
import { PageHeader, Divider } from '../components/ui'
import { SessionCard } from '../components/SessionCard'
import { useT } from '../i18n'
import { api, type ChainBlock, type Report } from '../lib/api'

type Tab = 'sessions' | 'chain' | 'limits'

export default function Reports({
  report,
  initialTab = 'sessions',
}: {
  report: Report | null
  initialTab?: Tab
}) {
  const t = useT()
  const [tab, setTab] = useState<Tab>(initialTab)
  const [blocks, setBlocks] = useState<ChainBlock[]>([])
  const [chainErr, setChainErr] = useState<string | null>(null)

  useEffect(() => {
    if (tab !== 'chain') return
    api
      .chain()
      .then((r) => setBlocks(r.blocks ?? []))
      .catch((e) => setChainErr(e.message))
  }, [tab])

  const TABS: { id: Tab; label: string }[] = [
    { id: 'sessions', label: t('Captures') },
    { id: 'chain', label: t('Evidence chain') },
    { id: 'limits', label: t('Known limitations') },
  ]

  return (
    <div>
      <PageHeader
        title={TABS.find((x) => x.id === tab)!.label}
        meta={report ? report.source.path : undefined}
      />
      <Divider />

      <nav className="mb-5 flex gap-1.5" aria-label={t('Sections')}>
        {TABS.map((x) => (
          <button
            key={x.id}
            onClick={() => setTab(x.id)}
            aria-current={tab === x.id}
            className={`rounded-full px-3.5 py-1.5 text-[12.5px] font-medium transition-colors ${
              tab === x.id
                ? 'bg-zinc-900 text-white'
                : 'border border-[#E4E4E7] bg-white text-zinc-700 hover:bg-[#F1EEE9]'
            }`}
          >
            {x.label}
          </button>
        ))}
      </nav>

      {tab === 'sessions' && (
        <>
          {!report ? (
            <p className="text-[13px] text-zinc-500">{t('No capture analysed yet')}</p>
          ) : (
            <div className="space-y-3">
              {report.sessions.map((s) => (
                <SessionCard key={s.session_id} session={s} />
              ))}
            </div>
          )}
        </>
      )}

      {tab === 'chain' && (
        <div className="space-y-4">
          {report?.evidence && (
            <div className="rounded-xl border border-[#E4E4E7] bg-white p-4 text-[12.5px] leading-relaxed">
              <dl className="grid gap-x-6 gap-y-1.5 sm:grid-cols-2">
                <div className="flex gap-2">
                  <dt className="text-zinc-500">{t('Chain valid')}</dt>
                  <dd className="font-mono text-zinc-800">{report.evidence.chain_id}</dd>
                </div>
                <div className="flex gap-2">
                  <dt className="text-zinc-500">{t('Block')}</dt>
                  <dd className="font-mono text-zinc-800">{report.evidence.block_index ?? '—'}</dd>
                </div>
                <div className="flex gap-2">
                  <dt className="text-zinc-500">{t('Not anchored')}</dt>
                  <dd className="font-mono text-zinc-800">
                    {t(`chain.${report.evidence.chain_state}`)}
                  </dd>
                </div>
                {report.evidence.block_hash && (
                  <div className="flex gap-2">
                    <dt className="text-zinc-500">SHA-256</dt>
                    <dd className="min-w-0 break-all font-mono text-zinc-800">
                      {report.evidence.block_hash}
                    </dd>
                  </div>
                )}
              </dl>
              <p className="mt-3 border-t border-[#F1EEE9] pt-2.5 text-zinc-600">
                {t('A clean report is not proof of a compliant control; it reflects only the traffic present in the supplied capture.')}
              </p>
            </div>
          )}

          {chainErr && <p className="text-[12.5px] text-[#C2410C]">{t('Error: {e}', { e: chainErr })}</p>}

          <div className="overflow-x-auto rounded-xl border border-[#E4E4E7] bg-white">
            <table className="w-full text-left text-[12.5px]">
              <thead className="border-b border-[#E4E4E7] text-[10.5px] uppercase tracking-wider text-zinc-400">
                <tr>
                  <th className="px-3 py-2 font-medium">{t('Block')}</th>
                  <th className="px-3 py-2 font-medium">Hash</th>
                  <th className="px-3 py-2 font-medium">{t('Difficulty')}</th>
                  <th className="px-3 py-2 font-medium">{t('Not anchored')}</th>
                  <th className="px-3 py-2 font-medium">{t('Transaction')}</th>
                </tr>
              </thead>
              <tbody>
                {blocks.map((b) => (
                  <tr key={b.index} className="border-b border-[#F1EEE9] last:border-0">
                    <td className="px-3 py-2 font-mono text-zinc-700">{b.index}</td>
                    <td className="px-3 py-2 font-mono text-zinc-500">{b.hash.slice(0, 20)}…</td>
                    <td className="px-3 py-2 font-mono text-zinc-500">{b.difficulty}</td>
                    <td className="px-3 py-2">
                      {b.anchored ? (
                        <span className="text-[#3f6f4f]">
                          {b.anchor_provider} · {b.anchor_tx?.slice(0, 12)}…
                        </span>
                      ) : (
                        <span className="text-zinc-400">{t('chain.pending')}</span>
                      )}
                    </td>
                    <td className="px-3 py-2 font-mono text-[11px] text-zinc-400">
                      {b.anchor_tx ?? '—'}
                    </td>
                  </tr>
                ))}
                {!blocks.length && !chainErr && (
                  <tr>
                    <td colSpan={5} className="px-3 py-4 text-center text-zinc-400">
                      —
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === 'limits' && (
        <div className="space-y-4">
          <section className="rounded-xl border border-[#E4E4E7] bg-white p-4">
            <h2 className="mb-2 text-[11px] uppercase tracking-wider text-zinc-400">
              {t('Limitations')}
            </h2>
            <ul className="space-y-1.5">
              {(report?.limitations ?? []).map((l, i) => (
                <li key={i} className="flex items-start gap-2 text-[12.5px] leading-relaxed text-zinc-600">
                  <span className="mt-px shrink-0 text-zinc-400">▸</span>
                  <span>{l}</span>
                </li>
              ))}
              {!report && <li className="text-[12.5px] italic text-zinc-400">—</li>}
            </ul>
          </section>

          <section className="rounded-xl border border-[#E4E4E7] bg-white p-4">
            <h2 className="mb-2 text-[11px] uppercase tracking-wider text-zinc-400">
              {t('What this build cannot see')}
            </h2>
            <CapabilitiesList />
          </section>
        </div>
      )}
    </div>
  )
}

function CapabilitiesList() {
  const t = useT()
  const [caps, setCaps] = useState<Awaited<ReturnType<typeof api.capabilities>> | null>(null)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    api.capabilities().then(setCaps).catch((e) => setErr(e.message))
  }, [])

  if (err) return <p className="text-[12.5px] text-[#C2410C]">{t('Error: {e}', { e: err })}</p>
  if (!caps) return <p className="text-[12.5px] text-zinc-400">…</p>

  return (
    <div className="space-y-4">
      <ul className="space-y-1.5">
        {caps.known_limitations.map((l, i) => (
          <li key={i} className="flex items-start gap-2 text-[12.5px] leading-relaxed text-zinc-600">
            <span className="mt-px shrink-0 text-zinc-400">▸</span>
            <span>{l}</span>
          </li>
        ))}
      </ul>

      <div>
        <h3 className="mb-1.5 text-[10.5px] uppercase tracking-wider text-zinc-400">TLS</h3>
        <dl className="space-y-1">
          {Object.entries(caps.tls_versions_visible).map(([k, v]) => (
            <div key={k} className="flex flex-col gap-0.5 text-[12px] sm:flex-row sm:gap-2">
              <dt className="shrink-0 font-mono text-zinc-700 sm:w-32">{k}</dt>
              <dd className="text-zinc-600">{v}</dd>
            </div>
          ))}
        </dl>
      </div>

      <div>
        <h3 className="mb-1.5 text-[10.5px] uppercase tracking-wider text-zinc-400">STARTTLS</h3>
        <ul className="flex flex-wrap gap-1.5">
          {caps.starttls_signatures.map((s) => (
            <li key={s} className="rounded bg-[#F1EEE9] px-1.5 py-0.5 font-mono text-[10.5px] text-zinc-700">
              {s}
            </li>
          ))}
        </ul>
      </div>

      <div>
        <h3 className="mb-1.5 text-[10.5px] uppercase tracking-wider text-zinc-400">
          {t('Protocol')}
        </h3>
        <ul className="flex flex-wrap gap-1.5">
          {caps.protocols.map((p) => (
            <li key={p} className="rounded bg-[#F1EEE9] px-1.5 py-0.5 text-[11px] text-zinc-700">
              {p}
            </li>
          ))}
        </ul>
      </div>
    </div>
  )
}
