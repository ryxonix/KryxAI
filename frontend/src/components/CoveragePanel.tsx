/**
 * Requirement coverage panel.
 *
 * The brief asks for a specific list of outputs. This panel answers it from the
 * scan's own evidence rather than from a claim in a README, and every row can be
 * expanded to show what proves it.
 *
 * The visual distinction that matters here is three-way, not two-way. A row with
 * no findings against it is not a gap: a capture where every server upgraded
 * cleanly *should* show a quiet row, and rendering that as an empty circle would
 * misreport a good result as a missing feature. So:
 *
 *   demonstrated     a finding or artefact proves the requirement was met
 *   clean            evaluated, nothing adverse found  (the good outcome)
 *   not_demonstrated this capture has nothing that exercises it
 *
 * Unmet rows are labelled as a property of the capture rather than a defect,
 * because that is what they are.
 */

import { useState } from 'react'
import { useT } from '../i18n'
import type { Coverage, CoverageItem, CoverageStatus } from '../lib/api'

function StatusIcon({ status }: { status: CoverageStatus }) {
  if (status === 'demonstrated') {
    return (
      <svg
        className="mt-px h-4 w-4 shrink-0 text-emerald-600"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth={2.5}
        aria-hidden="true"
      >
        <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
      </svg>
    )
  }
  if (status === 'clean') {
    return (
      <svg
        className="mt-px h-4 w-4 shrink-0 text-sky-500"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth={2}
        aria-hidden="true"
      >
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4" />
        <circle cx="12" cy="12" r="9" />
      </svg>
    )
  }
  return (
    <svg
      className="mt-px h-4 w-4 shrink-0 text-zinc-300"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="9" />
    </svg>
  )
}

function Row({ item }: { item: CoverageItem }) {
  const t = useT()
  const [open, setOpen] = useState(false)
  const hasEvidence = item.evidence.length > 0

  return (
    <li className="border-b border-[#F1F1F3] last:border-b-0">
      <button
        type="button"
        onClick={() => hasEvidence && setOpen((v) => !v)}
        aria-expanded={hasEvidence ? open : undefined}
        className={`flex w-full items-start gap-2.5 py-2 text-left ${
          hasEvidence ? 'cursor-pointer hover:bg-[#FAFAFB]' : 'cursor-default'
        }`}
      >
        <StatusIcon status={item.status} />
        <span className="min-w-0 flex-1">
          <span
            className={`block text-[12.5px] leading-snug ${
              item.status === 'not_demonstrated' ? 'text-zinc-400' : 'text-zinc-800'
            }`}
          >
            {item.requirement}
          </span>
          <span className="mt-0.5 block text-[11px] leading-relaxed text-zinc-500">
            {item.detail}
          </span>
        </span>
        {hasEvidence && (
          <span className="mt-px shrink-0 font-mono text-[10px] text-zinc-400">
            {open ? t('Hide evidence') : t('{n} evidence', { n: item.evidence.length })}
          </span>
        )}
      </button>
      {open && hasEvidence && (
        <ul className="mb-2 ml-6 space-y-0.5 border-l border-[#E4E4E7] pl-3">
          {item.evidence.map((e, i) => (
            <li key={i} className="font-mono text-[10.5px] leading-relaxed text-zinc-500">
              {e}
            </li>
          ))}
        </ul>
      )}
    </li>
  )
}

export function CoveragePanel({ coverage }: { coverage: Coverage }) {
  const t = useT()
  const [showAll, setShowAll] = useState(false)

  const { demonstrated, clean, not_demonstrated: unmet } = coverage.summary
  // Unmet rows are shown first only when they exist, since they are the ones a
  // reviewer should be asked about rather than discovering later.
  const ordered = [...coverage.items].sort((a, b) => {
    if (a.status !== b.status) {
      if (a.status === 'not_demonstrated') return -1
      if (b.status === 'not_demonstrated') return 1
    }
    return 0
  })
  const visible = showAll ? ordered : ordered.slice(0, 8)

  return (
    <section className="rounded-xl border border-[#E4E4E7] bg-white p-5">
      <div className="mb-1 flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="font-serif text-[15px] font-semibold text-zinc-900">
          {t('Requirement coverage')}
        </h2>
        <span className="font-mono text-[11px] text-zinc-500">
          {demonstrated} {t('evidenced')} · {clean} {t('checked, clean')} · {unmet} {t('not in this capture')}
        </span>
      </div>
      <p className="mb-3 text-[11.5px] leading-relaxed text-zinc-500">
        {t(
          'Derived from this scan’s own output rather than asserted. A clean row means the requirement was evaluated across the sessions and nothing adverse was found, which is the desired outcome. An empty circle means this particular capture contains nothing that exercises it.',
        )}
      </p>

      <ul className="-mx-1">
        {visible.map((item, i) => (
          <Row key={`${item.requirement}-${i}`} item={item} />
        ))}
      </ul>

      {ordered.length > 8 && (
        <button
          type="button"
          className="mt-2 text-[12px] underline underline-offset-2"
          onClick={() => setShowAll((v) => !v)}
        >
          {showAll ? t('Show fewer') : t('Show all {n} requirements', { n: ordered.length })}
        </button>
      )}
    </section>
  )
}
