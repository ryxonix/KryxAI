import { useCallback, useState } from 'react'
import { TopBar, Sidebar, type NavSection } from './components/ui'
import { CriticalAlert } from './components/ShieldBanner'
import Dashboard from './pages/Dashboard'
import Findings from './pages/Findings'
import Reports from './pages/Reports'
import Scan from './pages/Scan'
import { LanguageProvider, useT } from './i18n'
import { api, type Finding, type Report, type ScanSummary } from './lib/api'

type View = 'dashboard' | 'scan' | 'findings' | 'reports'

function AppInner() {
  const t = useT()
  const [view, setView] = useState<View>('dashboard')
  const [report, setReport] = useState<Report | null>(null)
  const [summary, setSummary] = useState<ScanSummary | null>(null)
  // Track WHICH scan the operator dismissed, not a boolean. Deriving
  // "is it showing" from the id removes the need to reset state in an effect,
  // and re-opening the alert for a new scan falls out for free.
  const [dismissedFor, setDismissedFor] = useState<string | null>(null)

  const load = useCallback(async (scanId: string) => {
    try {
      setReport(await api.report(scanId))
    } catch {
      // The backend holds reports in process memory only, so a restart or a
      // second worker makes the id unknown. Say so rather than showing nothing.
      setReport(null)
      setSummary((s) => (s ? { ...s, scan_id: scanId } : s))
    }
  }, [])

  const onScanned = useCallback(
    async (s: ScanSummary) => {
      setSummary(s)
      setView('dashboard')
      await load(s.scan_id)
    },
    [load],
  )

  // Only a critical finding opens the blocking alert. High severity stays inline.
  const critical: Finding | null =
    report?.findings.find((f) => f.severity === 'critical') ?? null
  const alertVisible = critical !== null && dismissedFor !== report?.evidence.scan_id

  const SECTIONS: NavSection[] = [
    {
      id: 'analysis',
      label: t('Passive mail-security forensics'),
      items: [
        { id: 'dashboard', label: t('Overview') },
        { id: 'scan', label: t('New scan') },
        { id: 'findings', label: t('Findings') },
      ],
    },
    {
      id: 'evidence',
      label: t('Evidence chain'),
      landing: 'reports',
      items: [],
    },
  ]

  return (
    <div className="min-h-screen">
      <TopBar onNav={(id) => setView(id as View)} />
      <div className="mx-auto flex max-w-[1400px]">
        <Sidebar sections={SECTIONS} active={view} onNavigate={(id) => setView(id as View)} />
        <main className="min-w-0 flex-1 px-6 py-8 md:px-10 lg:px-12">
          <div className="mx-auto max-w-3xl">
            {view === 'dashboard' && <Dashboard report={report} onNavigate={(id) => setView(id as View)} />}
            {view === 'scan' && <Scan onScanned={onScanned} />}
            {view === 'findings' && <Findings report={report} />}
            {view === 'reports' && <Reports report={report} />}
          </div>
        </main>
      </div>
      <footer className="border-t border-[#E4E4E7] py-6">
        <p className="mx-auto max-w-[1400px] px-6 text-center text-[12.5px] leading-relaxed text-zinc-500">
          {t('KryxAI')} — {t('Passive mail-security forensics')}. {t('This is not a compliance determination.')}
          {summary && (
            <span className="ml-1 font-mono text-zinc-400">
              scan {summary.scan_id.slice(0, 12)}… · {summary.chain_state}
            </span>
          )}
        </p>
      </footer>

      {alertVisible && critical && (
        <CriticalAlert
          finding={critical}
          onDismiss={() => setDismissedFor(report?.evidence.scan_id ?? null)}
        />
      )}
    </div>
  )
}

export default function App() {
  return (
    <LanguageProvider>
      <AppInner />
    </LanguageProvider>
  )
}
