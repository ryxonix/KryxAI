/**
 * Minimal History API routing.
 *
 * Four views do not justify a router dependency, and the app is a static
 * bundle that has to keep working when opened from a file path, so navigation
 * is built on `history.pushState` plus a `popstate` listener instead.
 *
 * Unknown paths resolve to the overview rather than a dead end. That is a
 * deliberate choice for an evidence tool: a mistyped URL should land on
 * something real, not a blank page that looks like data loss.
 */

import { useCallback, useEffect, useState } from 'react'

export type View = 'dashboard' | 'scan' | 'findings' | 'reports'

/** The four views, in the order they appear in the sidebar. */
export const VIEWS: View[] = ['dashboard', 'scan', 'findings', 'reports']

/** Canonical, human-readable path per view. `/` is the overview. */
export const PATHS: Record<View, string> = {
  dashboard: '/',
  scan: '/scan',
  findings: '/findings',
  reports: '/evidence',
}

const PATH_TO_VIEW = new Map<string, View>(
  (Object.entries(PATHS) as [View, string][]).map(([view, path]) => [path, view]),
)

/** Legacy ids that predate real URLs, kept working so old links still land. */
const ID_ALIASES: Record<string, View> = {
  dashboard: 'dashboard',
  scan: 'scan',
  findings: 'findings',
  reports: 'reports',
}

export function viewFromPath(pathname: string): View {
  const clean = pathname.replace(/\/+$/, '') || '/'
  const direct = PATH_TO_VIEW.get(clean)
  if (direct) return direct
  const alias = ID_ALIASES[clean.replace(/^\//, '')]
  return alias ?? 'dashboard'
}

/** Read the current view from the address bar. */
export function currentView(): View {
  if (typeof window === 'undefined') return 'dashboard'
  return viewFromPath(window.location.pathname)
}

/**
 * Navigate to a view.
 *
 * `replace` is used for the initial normalisation so a deep link to `/` does
 * not leave a spurious extra history entry behind.
 */
export function navigate(view: View, opts: { replace?: boolean } = {}): void {
  const path = PATHS[view]
  if (typeof window === 'undefined') return
  if (window.location.pathname === path) return
  if (opts.replace) window.history.replaceState({ view }, '', path)
  else window.history.pushState({ view }, '', path)
}

/**
 * Track the current view, synchronised with the address bar.
 *
 * Back and forward work because the listener reads `window.location` rather
 * than the state it would otherwise have set, so a history entry created by
 * anything else still resolves correctly.
 */
export function useRouter(): [View, (view: View) => void] {
  const [view, setView] = useState<View>(currentView)

  useEffect(() => {
    const onPop = () => setView(currentView())
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  }, [])

  // Normalise a deep link that arrived as a legacy or malformed path, so the
  // address bar always shows the canonical URL for what is on screen.
  useEffect(() => {
    const canonical = PATHS[view]
    if (window.location.pathname !== canonical) {
      window.history.replaceState({ view }, '', canonical)
    }
  }, [view])

  const go = useCallback((next: View) => {
    navigate(next)
    setView(next)
    // A new view starts at the top, the way a real page load would.
    window.scrollTo({ top: 0, behavior: 'instant' as ScrollBehavior })
  }, [])

  return [view, go]
}
