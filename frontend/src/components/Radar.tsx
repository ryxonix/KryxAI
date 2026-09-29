import { useMemo } from 'react'
import { useT } from '../i18n'
import { bandColor } from './RiskGauge'

export interface RadarAxis {
  key: string
  label: string
  /** 0-100, higher is better. */
  value: number
}

/**
 * Radar of the KryxAI posture dimensions.
 *
 * Every axis is "higher is better" and already a percentage, so a point sitting
 * near the outer ring means a strong dimension. Dimensions that were not
 * assessable are rendered as an explicit gap rather than being plotted as zero,
 * because "we could not measure this" and "we measured this as bad" are very
 * different statements.
 */
export function Radar({
  axes,
  notAssessed = [],
}: {
  axes: RadarAxis[]
  notAssessed?: string[]
}) {
  const t = useT()
  const sorted = useMemo(
    () => [...axes].sort((a, b) => (notAssessed.includes(a.key) ? 1 : 0) - (notAssessed.includes(b.key) ? 1 : 0)),
    [axes, notAssessed],
  )

  if (!sorted.length) {
    return (
      <p className="py-6 text-center text-[12px] italic text-zinc-400">
        {t('No dimensions could be scored from this capture.')}
      </p>
    )
  }

  const cx = 4
  const cy = 4
  const R = 3.25
  const angle0 = -Math.PI / 2
  const angleAt = (i: number) => angle0 + (2 * Math.PI / sorted.length) * i

  return (
    <div className="space-y-2.5">
      {sorted.map((ax) => {
        const missing = notAssessed.includes(ax.key)
        return (
          <div key={ax.key}>
            <div className="flex justify-between gap-2 text-[12.5px]">
              <span className="min-w-0 truncate text-zinc-800">{ax.label}</span>
              <span className="shrink-0 font-mono text-zinc-500">
                {missing ? t('Not assessed') : `${ax.value.toFixed(0)}%`}
              </span>
            </div>
            <div className="mt-1 h-[3px] rounded-full bg-[#F1EEE9]">
              <div
                className="h-[3px] rounded-full"
                style={{
                  width: `${Math.max(0, Math.min(100, ax.value))}%`,
                  background: bandColor(ax.value >= 90 ? 'A' : ax.value >= 70 ? 'B' : ax.value >= 50 ? 'C' : 'D'),
                  // A not-assessed dimension is drawn as a faint track only, so
                  // it never reads as a measured zero.
                  opacity: missing ? 0.25 : 1,
                  transition: 'width 0.4s cubic-bezier(0.25, 0.1, 0.25, 1)',
                }}
              />
            </div>
          </div>
        )
      })}

      <svg
        viewBox="0 0 800 800"
        className="mx-auto block w-48 max-w-full"
        role="img"
        aria-label={t('Scoring dimensions')}
      >
        {sorted.map((ax, i) => {
          const a = angleAt(i)
          const x = cx + Math.cos(a) * R
          const y = cy + Math.sin(a) * R
          return (
            <g key={ax.key}>
              <line
                x1={cx * 100}
                y1={cy * 100}
                x2={x * 100}
                y2={y * 100}
                stroke="#E4E4E7"
                strokeWidth="2"
              />
              <text
                x={x * 100 + (x < 0 ? -14 : 14)}
                y={y * 100 + 22}
                textAnchor={x < 0 ? 'end' : 'start'}
                fill="#71717A"
                fontSize="20"
                fontFamily="Inter, sans-serif"
              >
                {ax.label}
              </text>
            </g>
          )
        })}
        <circle cx={cx * 100} cy={cy * 100} r="8" fill="none" stroke="#E4E4E7" strokeWidth="2" />
        <circle cx={cx * 100} cy={cy * 100} r={R * 100} fill="none" stroke="#E4E4E7" strokeWidth="1.5" />
        {/* Connecting polygon across the scored dimensions. */}
        {sorted.every((ax) => !notAssessed.includes(ax.key)) && sorted.length > 2 && (
          <polygon
            fill="#7c5cbf"
            fillOpacity="0.10"
            stroke="#7c5cbf"
            strokeWidth="2.5"
            points={sorted
              .map((ax, i) => {
                const a = angleAt(i)
                const r = (Math.max(0, Math.min(100, ax.value)) / 100) * R
                return `${(cx + Math.cos(a) * r) * 100},${(cy + Math.sin(a) * r) * 100}`
              })
              .join(' ')}
          />
        )}
        {sorted.map((ax, i) => {
          if (notAssessed.includes(ax.key)) return null
          const a = angleAt(i)
          const r = (Math.max(0, Math.min(100, ax.value)) / 100) * R
          const x = cx + Math.cos(a) * r
          const y = cy + Math.sin(a) * r
          return (
            <circle
              key={`pt-${ax.key}`}
              cx={x * 100}
              cy={y * 100}
              r="9"
              fill={bandColor(ax.value >= 90 ? 'A' : ax.value >= 70 ? 'B' : ax.value >= 50 ? 'C' : 'D')}
              opacity="0.9"
              style={{ transition: 'cx 0.4s cubic-bezier(0.25, 0.1, 0.25, 1), cy 0.4s cubic-bezier(0.25, 0.1, 0.25, 1)' }}
            />
          )
        })}
      </svg>
    </div>
  )
}
