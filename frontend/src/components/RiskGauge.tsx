import { useMemo } from 'react'
import { useT } from '../i18n'

export function bandColor(band?: string): string {
  if (band === 'critical' || band === 'F') return '#DC2626'
  if (band === 'high' || band === 'D') return '#C2410C'
  if (band === 'medium' || band === 'C') return '#b45309'
  // A report with no grade is neutral, not good. Without this the fallthrough
  // would paint an absent grade the same green as an A, which reads as a
  // passing posture that was never actually measured.
  if (band === 'unknown' || band === undefined) return '#71717A'
  return '#3f6f4f'
}

/**
 * Circular posture gauge.
 *
 * KryxAI's posture score is 0-100 where HIGH IS GOOD, so the arc is filled in
 * proportion to the score and coloured by grade. This is deliberately not a
 * "risk" gauge: a full ring must not read as danger.
 */
export function RiskGauge({
  score,
  grade,
  label,
  caption,
}: {
  score: number
  grade: string
  label?: string
  caption?: string
}) {
  const t = useT()
  const R = 74
  const CIRC = 2 * Math.PI * R
  const frac = Math.max(0, Math.min(1, score / 100))
  const color = bandColor(grade)
  return (
    <div className="flex flex-col items-center">
      <svg width="180" height="180" viewBox="0 0 180 180" role="img" aria-label={`${label ?? t('Security posture')}: ${grade}`}>
        <circle cx="90" cy="90" r={R} fill="none" stroke="#F1EEE9" strokeWidth="9" />
        <circle
          cx="90"
          cy="90"
          r={R}
          fill="none"
          stroke={color}
          strokeWidth="9"
          strokeLinecap="round"
          strokeDasharray={`${frac * CIRC} ${CIRC}`}
          transform="rotate(-90 90 90)"
          style={{ transition: 'stroke-dasharray 0.5s cubic-bezier(0.25, 0.1, 0.25, 1), stroke 0.3s ease' }}
        />
        <text
          x="90"
          y="92"
          textAnchor="middle"
          fontSize="40"
          fontWeight="700"
          fill="#18181B"
          fontFamily="Georgia, serif"
          style={{ letterSpacing: '-0.02em' }}
        >
          {score.toFixed(0)}
        </text>
        <text x="90" y="114" textAnchor="middle" fontSize="10.5" fill="#71717A" style={{ letterSpacing: '0.08em' }}>
          {caption ?? t('POSTURE')}
        </text>
      </svg>
      <div className="mt-1.5 text-[12px] font-semibold" style={{ color }}>
        {grade} · {label}
      </div>
    </div>
  )
}

export interface Factor {
  label: string
  value: number
  max?: number
  color?: string
  fmt?: (v: number) => string
}

/**
 * Explainable factor rows. Fed either with a finding's risk contributions or
 * with posture dimensions, so the same visual language explains both "why is
 * this finding scored" and "where did the posture come from".
 */
export function XaiBars({
  factors,
  emptyLabel,
}: {
  factors: Factor[]
  emptyLabel?: string
}) {
  const t = useT()
  return (
    <div className="space-y-2.5">
      {factors.map((f) => {
        const max = f.max ?? 10
        const pct = max > 0 ? Math.min(100, (f.value / max) * 100) : 0
        return (
          <div key={f.label}>
            <div className="flex justify-between gap-2 text-[12.5px]">
              <span className="min-w-0 truncate text-zinc-800">{f.label}</span>
              <span className="shrink-0 font-mono text-zinc-500">
                {f.fmt ? f.fmt(f.value) : f.value.toFixed(1)}
              </span>
            </div>
            <div className="mt-1 h-[3px] rounded-full bg-[#F1EEE9]">
              <div
                className="h-[3px] rounded-full"
                style={{
                  width: `${pct}%`,
                  background: f.color ?? '#71717A',
                  transition: 'width 0.4s cubic-bezier(0.25, 0.1, 0.25, 1)',
                }}
              />
            </div>
          </div>
        )
      })}
      {!factors.length && (
        <p className="text-[11.5px] italic text-zinc-400">
          {emptyLabel ?? t('No further detail available.')}
        </p>
      )}
    </div>
  )
}

/** Posture dimensions as explainable bars. */
export function dimensionFactors(
  dimensions: Record<string, number>,
  t: (k: string) => string,
): Factor[] {
  return Object.entries(dimensions).map(([k, v]) => ({
    label: t(k),
    value: v,
    max: 100,
    fmt: (x: number) => `${x.toFixed(0)}%`,
    color: bandColor(v >= 90 ? 'A' : v >= 70 ? 'B' : v >= 50 ? 'C' : 'D'),
  }))
}

/** A finding's scored contributions as explainable bars. */
export function useRiskFactors(finding: any): Factor[] {
  return useMemo(() => {
    const c = finding?.risk?.contributions
    if (!Array.isArray(c) || !c.length) return []
    const max = Math.max(
      Number(finding?.risk?.total ?? 0),
      ...c.map((y: any) => Number(y.points ?? 0)),
      1,
    )
    return c.map((x: any) => ({
      label: String(x.label ?? '').replace(/_/g, ' '),
      value: Number(x.points ?? 0),
      max,
      fmt: (v: number) => v.toFixed(1),
      color: '#7c5cbf',
    }))
  }, [finding])
}
