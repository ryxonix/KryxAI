import { useRef, useState } from 'react'
import { PageHeader, Divider } from '../components/ui'
import { useT } from '../i18n'
import { api, ApiError, type ScanSummary } from '../lib/api'

const ACCEPT = '.pcap,.pcapng,.cap,.dmp'

export default function Scan({
  onScanned,
}: {
  onScanned: (summary: ScanSummary) => void
}) {
  const t = useT()
  const inputRef = useRef<HTMLInputElement>(null)
  const [file, setFile] = useState<File | null>(null)
  const [dragging, setDragging] = useState(false)
  const [serverPath, setServerPath] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function run(fn: () => Promise<ScanSummary>) {
    setBusy(true)
    setError(null)
    try {
      onScanned(await fn())
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  function pick(f: File | undefined) {
    if (!f) return
    setError(null)
    setFile(f)
  }

  return (
    <div>
      <PageHeader
        title={t('New scan')}
        meta={t('Passive mail-security forensics')}
      />
      <Divider />

      <p className="mb-5 rounded-lg border border-[#E4E4E7] bg-white px-3.5 py-2.5 text-[12.5px] leading-relaxed text-zinc-600">
        {t('Observes an existing capture. It never probes, scans or modifies anything.')}
      </p>

      {/* upload */}
      <section className="mb-6">
        <h2 className="mb-2 text-[11px] uppercase tracking-wider text-zinc-400">
          {t('Choose a capture')}
        </h2>
        <div
          onDragOver={(e) => {
            e.preventDefault()
            setDragging(true)
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => {
            e.preventDefault()
            setDragging(false)
            pick(e.dataTransfer.files?.[0])
          }}
          onClick={() => inputRef.current?.click()}
          className={`cursor-pointer rounded-xl border-2 border-dashed px-6 py-10 text-center transition-colors ${
            dragging ? 'border-zinc-900 bg-[#F1EEE9]' : 'border-[#E4E4E7] bg-white hover:bg-[#FAF8F5]'
          }`}
        >
          <input
            ref={inputRef}
            type="file"
            accept={ACCEPT}
            className="hidden"
            onChange={(e) => pick(e.target.files?.[0])}
          />
          <p className="text-[13.5px] text-zinc-700">
            {file ? (
              <span className="font-mono">{file.name}</span>
            ) : (
              t('Drop a .pcap or .pcapng file here, or choose one from disk')
            )}
          </p>
          {file && (
            <p className="mt-1 text-[11.5px] text-zinc-400">{(file.size / 1024).toFixed(1)} KiB</p>
          )}
        </div>
        <button
          disabled={!file || busy}
          onClick={() => file && run(() => api.upload(file))}
          className="mt-3 rounded-full bg-zinc-900 px-5 py-2 text-[13px] font-semibold text-white transition-colors hover:bg-zinc-700 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {busy ? t('Analysing...') : t('Analyse capture')}
        </button>
      </section>

      {/* server-side path */}
      <section>
        <h2 className="mb-2 text-[11px] uppercase tracking-wider text-zinc-400">
          {t('Scan a file already on the server')}
        </h2>
        <div className="flex flex-wrap gap-2">
          <input
            value={serverPath}
            onChange={(e) => setServerPath(e.target.value)}
            placeholder="/var/lib/kryxai/captures/office.pcap"
            aria-label={t('Server-side path')}
            className="min-w-[16rem] flex-1 rounded-lg border border-[#E4E4E7] px-3 py-2 font-mono text-[12.5px] outline-none focus:border-zinc-400"
          />
          <button
            disabled={!serverPath.trim() || busy}
            onClick={() => run(() => api.scanPath(serverPath.trim()))}
            className="rounded-full border border-zinc-900 px-5 py-2 text-[13px] font-semibold text-zinc-900 transition-colors hover:bg-zinc-900 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
          >
            {busy ? t('Analysing...') : t('Analyse capture')}
          </button>
        </div>
      </section>

      {error && (
        <div className="mt-5 rounded-lg border border-[#C2410C] bg-[#FCEEE7] px-3.5 py-2.5 text-[12.5px] leading-relaxed text-[#C2410C]">
          {t('Error: {e}', { e: error })}
        </div>
      )}
    </div>
  )
}
