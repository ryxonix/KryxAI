# KryxAI — Frontend

React + TypeScript + Vite dashboard for KryxAI, a passive mail-cryptographic
forensics engine. Talks to the FastAPI backend (`kryxai/api.py`) over `/api`,
`/ws` and `/health`, which are proxied to the backend in dev (see
`vite.config.ts`).

## Run

Use `../run_kavach.bat` (Windows) or `../run_kavach.sh` (POSIX) for the
full stack, including the backend. To run only the UI against an
already-running backend:

```sh
npm install
npm run dev        # http://localhost:5173
npm run build      # typecheck + production bundle (dist/)
```

### Backend port

The dev proxy target defaults to `http://localhost:8000` and is overridable:

```sh
VITE_API_TARGET=http://127.0.0.1:8010 npm run dev     # POSIX
$env:VITE_API_TARGET = 'http://127.0.0.1:8010'; npm run dev   # PowerShell
```

Set this whenever port 8000 is already occupied. A hardcoded target silently
forwards to whatever else holds the port, which looks like a working app
while serving a different server's data.

## Wiring

- `src/api` convention: fetch requests use `apiBase()` (`src/components/ui.tsx`),
  which returns an empty string when served from the same origin as the backend
  (e.g. behind a reverse proxy).
- WebSocket sessions: `wsBase()` in the same file.
- UI text goes through `src/i18n.tsx`. `en` is the source language and `hi` is
  a full translation. Add any new user-facing string to both dictionaries.
