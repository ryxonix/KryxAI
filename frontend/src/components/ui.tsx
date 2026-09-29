import { useEffect, useRef, useState } from 'react'
import { LANGS, LANG_NAMES, useI18n } from '../i18n'
import type { View } from '../router'

function readEnvBaseTrimmed(): string {
  const env = (import.meta as any).env ?? {}
  const raw = (env as any).VITE_API_BASE
  return typeof raw === 'string' ? raw.trim() : ''
}

export function apiBase(): string {
  const base = readEnvBaseTrimmed()
  if (base) return base.replace(/\/$/, '')
  // On the dev server the request stays same-origin and the proxy in
  // vite.config.ts forwards it. Hardcoding an absolute :8000 origin here would
  // bypass the proxy and break the moment the backend runs on another port.
  return ''
}

/* ------------------------------ Button helper ------------------------------ */
export const btn = (extra = '') => `btn-pill ${extra}`.trim()

/* --------------------------------- Icons ---------------------------------- */
export const Chevron = ({ open, className = '' }: { open?: boolean; className?: string }) => (
  <svg
    viewBox="0 0 16 16"
    width="14"
    height="14"
    className={`transition-transform duration-200 ${open ? 'rotate-90' : ''} ${className}`}
    fill="none"
    stroke="currentColor"
    strokeWidth="1.6"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <path d="M6 3.5 10.5 8 6 12.5" />
  </svg>
)
export const Caret = () => (
  <svg viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
    <path d="M4 6l4 4 4-4" />
  </svg>
)
export const Globe = () => (
  <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.4">
    <circle cx="8" cy="8" r="6.2" />
    <path d="M1.8 8h12.4M8 1.8c-4.2 4-4.2 8.4 0 12.4 4.2-4 4.2-8.4 0-12.4z" />
  </svg>
)

/** KryxAI monogram — a stylised K. */
export function BrandMark({ size = 26 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" aria-label="KryxAI logo">
      <rect width="32" height="32" rx="8" fill="#2563EB" />
      <path
        d="M11 7v18M11 16.5 20 7M11 16.5 20 25"
        stroke="#fff"
        strokeWidth="2.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

/* ------------------------------ Top bar header ----------------------------- */
export function TopBar({
  right,
  onNav,
}: {
  right?: React.ReactNode
  onNav?: (view: View) => void
}) {
  return (
    <header className="sticky top-0 z-30 border-b border-[#E4E4E7] bg-[#FAF8F5]/90 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-[1400px] items-center justify-between px-6">
        <button onClick={() => onNav?.('dashboard')} className="flex items-center gap-2.5">
          <BrandMark />
          <span className="text-[19px] font-bold tracking-tight text-zinc-900">
            KryxAI
          </span>
        </button>
        <div className="flex items-center gap-6">{right ?? <SettingsMenu />}</div>
      </div>
    </header>
  )
}

function SettingsMenu() {
  const { lang, setLang } = useI18n()
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const h = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', h)
    return () => document.removeEventListener('mousedown', h)
  }, [])
  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-1.5 rounded-full border border-[#E4E4E7] bg-white px-3.5 py-1.5 text-[13px] font-medium text-zinc-800 transition-colors hover:bg-[#F1EEE9]"
      >
        <Globe />
        {LANG_NAMES[lang]}
        <Caret />
      </button>
      {open && (
        <div className="rise absolute right-0 mt-2 w-48 rounded-xl border border-[#E4E4E7] bg-white p-1.5 shadow-lg shadow-zinc-900/5">
          {LANGS.map((l) => (
            <button
              key={l}
              onClick={() => {
                setLang(l)
                setOpen(false)
              }}
              className={`flex w-full items-center justify-between rounded-lg px-3 py-2 text-[13px] transition-colors hover:bg-[#F1EEE9] ${
                l === lang ? 'font-semibold text-zinc-900' : 'text-zinc-700'
              }`}
            >
              {LANG_NAMES[l]}
              {l === lang && <span className="text-[#2563EB]">●</span>}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

/* ------------------------------ Sidebar shell ------------------------------ */
export type NavItem = { id: View; label: string; badge?: string }
export type NavSection = { id: string; label: string; items: NavItem[]; landing?: View }

export function Sidebar({
  sections,
  active,
  onNavigate,
  header,
}: {
  sections: NavSection[]
  active: View
  onNavigate: (view: View) => void
  header?: React.ReactNode
}) {
  const [openSet, setOpenSet] = useState<Set<string>>(
    () => new Set(sections.filter((s) => s.items.some((i) => i.id === active)).map((s) => s.id)),
  )
  const toggle = (id: string) => {
    const willOpen = !openSet.has(id)
    setOpenSet((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
    return willOpen
  }

  return (
    <aside className="sticky top-16 hidden h-[calc(100vh-4rem)] w-64 shrink-0 overflow-y-auto border-r border-[#E4E4E7] pb-10 pt-6 lg:block">
      {header && <div className="px-5 pb-4">{header}</div>}
      <nav className="space-y-0.5 px-3">
        {sections.map((s) => {
          const open = openSet.has(s.id)
          return (
            <div key={s.id} className="mb-1">
              <button
                onClick={() => {
                  if (toggle(s.id) && s.landing) onNavigate(s.landing)
                }}
                aria-expanded={open}
                className={`flex w-full items-center justify-between rounded-lg px-3 py-2 text-left text-[13.5px] font-bold text-zinc-900 transition-colors hover:bg-[#F1EEE9] ${
                  active === s.id ? 'bg-[#F1EEE9]' : ''
                }`}
              >
                <span>{s.label}</span>
                <span className="text-zinc-400">
                  <Chevron open={open} />
                </span>
              </button>
              {open && (
                <div className="mb-2 ml-3 mt-0.5 space-y-0.5 border-l border-[#E4E4E7] pl-2">
                  {s.items.map((i) => {
                    const isActive = i.id === active
                    return (
                      <button
                        key={i.id}
                        onClick={() => onNavigate(i.id)}
                        aria-current={isActive ? 'page' : undefined}
                        className={`flex w-full items-center justify-between rounded-lg px-3 py-1.5 text-left text-[13.5px] transition-colors ${
                          isActive
                            ? 'bg-white font-semibold text-zinc-900 shadow-sm shadow-zinc-900/5 ring-1 ring-[#E4E4E7]'
                            : 'font-medium text-zinc-600 hover:bg-[#F1EEE9] hover:text-zinc-900'
                        }`}
                      >
                        <span>{i.label}</span>
                        {i.badge && (
                          <span className="rounded-full bg-[#FCEEE7] px-1.5 py-0.5 text-[10px] font-bold text-[#C2410C]">
                            {i.badge}
                          </span>
                        )}
                      </button>
                    )
                  })}
                </div>
              )}
            </div>
          )
        })}
      </nav>
    </aside>
  )
}

/* ------------------------------ Page scaffold ------------------------------ */
export function Breadcrumbs({ trail }: { trail: string[] }) {
  return (
    <nav className="flex flex-wrap items-center gap-1.5 text-[13px] text-zinc-500">
      {trail.map((t, i) => (
        <span key={i} className="flex items-center gap-1.5">
          {i > 0 && <Chevron className="text-zinc-300" />}
          <span className={i === trail.length - 1 ? 'text-zinc-700' : ''}>{t}</span>
        </span>
      ))}
    </nav>
  )
}

export function PageHeader({
  title,
  meta,
  actions,
}: {
  title: string
  meta?: React.ReactNode
  actions?: React.ReactNode
}) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4">
      <div className="max-w-3xl">
        <h1 className="font-serif text-[34px] font-bold leading-tight tracking-tight text-zinc-900 md:text-[40px]">
          {title}
        </h1>
        {meta && <div className="mt-2 text-[13.5px] text-zinc-500">{meta}</div>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

export function Divider() {
  return <div className="my-7 border-b border-[#E4E4E7]" />
}

/* -------------------------------- Sparkline -------------------------------- */
export function Sparkline({
  values,
  color = '#2563EB',
  height = 56,
}: {
  values: number[]
  color?: string
  height?: number
}) {
  const w = 600
  const max = Math.max(...values, 0.001)
  const pts = values
    .map((v, i) => `${(i / Math.max(values.length - 1, 1)) * w},${height - (v / max) * (height - 4) - 2}`)
    .join(' ')
  return (
    <svg viewBox={`0 0 ${w} ${height}`} preserveAspectRatio="none" className="block w-full" style={{ height }}>
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.8" strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  )
}
