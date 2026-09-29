import { useCallback, useEffect, useState } from 'react'
import { TopBar, Sidebar, type NavSection } from './components/ui'
import { CriticalAlert } from './components/ShieldBanner'
import Dashboard from './pages/Dashboard'
import Findings from './pages/Findings'
import Reports from './pages/Reports'
import Scan from './pages/Scan'
import { LanguageProvider, useT } from './i18n'
import { useRouter } from './router'
import { api, type Finding, type Report, type ScanSummary } from './lib/api'

const LAST_SCAN_KEY = 'kryxai-last-scan'

function AppInner() {
  const t = useT()
  const [view, setView] = useRouter()
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
      // The report may have been removed, or the id may be unknown to this
      // deployment. Say so rather than showing nothing.
      setReport(null)
      setSummary((s) => (s ? { ...s, scan_id: scanId } : s))
    }
  }, [])

  // Restore the last scan on mount so a refresh does not silently empty the
  // dashboard. The id is remembered locally; the report itself is rehydrated
  // by the backend from the reports directory, so this survives a restart too.
  useEffect(() => {
    let cancelled = false
    const restore = async () => {
      let scanId = localStorage.getItem(LAST_SCAN_KEY)
      if (!scanId) {
        // No local memory (first visit, or storage cleared): fall back to the
        // most recent report the backend still has on disk.
        try {
          const recent = await api.scans(1)
          if (recent.length) scanId = recent[0].scan_id
        } catch {
          return
        }
      }
      if (!scanId || cancelled) return
      try {
        const restored = await api.report(scanId)
        if (cancelled) return
        setReport(restored)
        const evidence = restored.evidence
        setSummary({
          scan_id: evidence.scan_id,
          block_index: evidence.block_index,
          posture_grade: restored.posture.grade,
          posture_score: restored.posture.score,
          findings: restored.findings.length,
          sessions: restored.sessions.length,
          chain_state: evidence.chain_state,
          report_files: restored.coverage?.report_files ?? {},
        })
      } catch {
        // The remembered scan is gone. Forget it rather than retrying on every
        // reload, but leave the current view untouched.
        localStorage.removeItem(LAST_SCAN_KEY)
      }
    }
    void restore()
    return () => {
      cancelled = true
    }
  }, [])

  const onScanned = useCallback(
    async (s: ScanSummary) => {
      setSummary(s)
      localStorage.setItem(LAST_SCAN_KEY, s.scan_id)
      setView('dashboard')
      await load(s.scan_id)
    },
    [load, setView],
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
        <TopBar onNav={setView} />
      <div className="mx-auto flex max-w-[1400px]">
        <Sidebar sections={SECTIONS} active={view} onNavigate={setView} />
        <main className="min-w-0 flex-1 px-6 py-8 md:px-10 lg:px-12">
          <div className="mx-auto max-w-3xl">
            {view === 'dashboard' && <Dashboard report={report} onNavigate={setView} />}
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
