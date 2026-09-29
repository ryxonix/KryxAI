/**
 * DPDP statutory mapping panel.
 *
 * This is deliberately the least confident-looking panel in the dashboard. A
 * compliance mapping reads like a determination, and this one is not: it is a
 * technical observation matched to statutory text that was transcribed from a
 * data file and not re-checked against the Gazette. The verification status is
 * therefore rendered as a banner rather than buried in a footnote, and the
 * Second Schedule note is shown next to every mapping so the Rs. 250 crore
 * figure can never be read as applying to a section 8 finding.
 *
 * It is part of the signed report, so the caveat is covered by the same
 * signature as the rest of the report rather than asserted alongside it.
 */

import { useState } from 'react'
import { useT } from '../i18n'
import type { ComplianceItem, ComplianceSummary } from '../lib/api'

function sectionTone(section: string): string {
  // Section 8 is the data-principal safeguard duty and carries no monetary
  // penalty; anything else in the Second Schedule does. Colouring them
  // differently is a nudge, not a legal classification.
  if (/8\(/.test(section)) return '#71717A'
  return '#b45309'
}

function Item({ item }: { item: ComplianceItem }) {
  const t = useT()
  const [open, setOpen] = useState(false)
  return (
    <li className="border-b border-[#F1F1F3] last:border-b-0">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full cursor-pointer items-start gap-2.5 py-2 text-left hover:bg-[#FAFAFB]"
      >
        <span
          className="mt-px shrink-0 rounded px-1.5 py-0.5 font-mono text-[10px]"
          style={{ color: sectionTone(item.provision.section), background: `${sectionTone(item.provision.section)}12` }}
        >
          {item.provision.section}
        </span>
        <span className="min-w-0 flex-1">
          <span className="block text-[12.5px] leading-snug text-zinc-800">
            <span className="font-mono text-[11px] text-zinc-500">{item.finding_code}</span>
            {item.endpoint ? <span className="ml-1.5 font-mono text-[11px] text-zinc-400">{item.endpoint}</span> : null}
          </span>
          <span className="mt-0.5 block text-[11px] leading-relaxed text-zinc-500">
            {item.observation}
          </span>
        </span>
        <span className="mt-px shrink-0 font-mono text-[10px] text-zinc-400">
          {open ? t('Hide detail') : t('Detail')}
        </span>
      </button>
      {open && (
        <div className="mb-2 ml-6 space-y-1.5 border-l border-[#E4E4E7] pl-3">
          <p className="text-[11px] leading-relaxed text-zinc-700">
            <span className="font-semibold">{item.provision.heading}</span>
          </p>
          <p className="text-[11px] italic leading-relaxed text-zinc-600">"{item.provision.text}"</p>
          <p className="text-[11px] leading-relaxed text-zinc-600">
            <span className="font-semibold">{t('Exposure:')}</span> {item.exposure}
          </p>
          <p className="text-[11px] leading-relaxed text-zinc-600">
            <span className="font-semibold">{t('Relevance:')}</span> {item.provision.relevance}
          </p>
          {item.caveats.map((c, i) => (
            <p key={i} className="text-[10.5px] leading-relaxed text-zinc-500">
              ▸ {c}
            </p>
          ))}
          <a
            href={item.provision.url}
            target="_blank"
            rel="noreferrer noopener"
            className="inline-block font-mono text-[10.5px] text-[#7c5cbf] underline underline-offset-2"
          >
            {item.provision.url}
          </a>
        </div>
      )}
    </li>
  )
}

export function CompliancePanel({ compliance }: { compliance: ComplianceSummary }) {
  const t = useT()
  const mapped = compliance.mapped_findings

  return (
    <section className="rounded-xl border border-[#E4E4E7] bg-white p-5">
      <div className="mb-1 flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="font-serif text-[15px] font-semibold text-zinc-900">
          {t('DPDP statutory mapping')}
        </h2>
        <span className="font-mono text-[11px] text-zinc-500">
          {mapped} {t('observation(s) mapped')}
        </span>
      </div>

      <div className="mb-3 rounded border border-[#C2410C]/30 bg-[#C2410C]/[0.06] px-3 py-2">
        <p className="text-[11.5px] font-semibold text-[#C2410C]">
          {t('Statutory text:')} {compliance.verification_status}
        </p>
        {compliance.verification_note ? (
          <p className="mt-0.5 text-[11px] leading-relaxed text-zinc-600">
            {compliance.verification_note}
          </p>
        ) : null}
      </div>

      {mapped === 0 ? (
        <p className="text-[12.5px] italic text-zinc-500">
          {t('No finding in this capture mapped to a DPDP provision.')}
        </p>
      ) : (
        <>
          <ul className="-mx-1">
            {compliance.items.map((item, i) => (
              <Item key={`${item.finding_code}-${item.provision.section}-${i}`} item={item} />
            ))}
          </ul>
          <p className="mt-3 text-[11px] leading-relaxed text-zinc-500">
            {compliance.second_schedule_note}
          </p>
        </>
      )}

      <p className="mt-3 border-t border-[#F1F1F3] pt-2 text-[11px] leading-relaxed text-zinc-500">
        {compliance.disclaimer}
      </p>
    </section>
  )
}
