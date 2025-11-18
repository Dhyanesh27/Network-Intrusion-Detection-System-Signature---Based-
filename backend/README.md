# NIDS Backend (mock)

This is a simple Node.js backend that exposes REST endpoints and a WebSocket endpoint to stream simulated packets and alerts for frontend development.

Run locally:

```powershell
cd backend
npm install
npm run dev
```

Open `http://localhost:4000/api/summary` and `/ws` is the WebSocket path.

Integration notes
- Replace simulated packet generation with real packet ingestion: either the OS agent pushes events to this server (over a secure channel) or the server reads from a local socket/device.
- For production, secure WebSocket and REST endoints with TLS and authentication (mTLS, API keys, JWT).
- For ML, you can either:
  - run the model inside the agent and forward scores to the server, or
  - host a model server (TensorFlow Serving, TorchServe, FastAPI) and query it from this backend.

Persistence, queueing, metrics and retention
-----------------------------------------
This backend now includes:
- SQLite persistence in `backend/nids.db` (tables: alerts, audit, signatures)
- Redis-backed ingest queue (`events` list). A worker (`backend/worker.js`) consumes events and persists alerts/audit entries.
- Prometheus metrics at `/metrics` (uses `prom-client`).
- Health endpoint at `/health`.
- Retention job that removes alerts older than `RETENTION_DAYS` (default 30) runs daily at 02:00 via cron.

Run everything locally (development):
1. Start Redis (e.g., Docker):

```powershell
docker run -p 6379:6379 -d redis:7
```

2. Start backend:

```powershell
cd backend
npm install
# set env optionally: $env:REQUIRE_MTLS='1'; $env:JWT_SECRET='secret'; $env:REDIS_URL='redis://127.0.0.1:6379'
npm run dev
```

3. Start worker in another terminal:

```powershell
cd backend
node worker.js
```

SIEM integration
- You can forward triage or alert events to a SIEM by setting `SIEM_URL` environment variable. The server will POST triage updates to that URL for downstream SOC integration.

Alert triage workflow
- The frontend now supports acknowledging, escalating, and annotating alerts. These updates are persisted to SQLite and forwarded to SIEM if configured.

Signature management
- CRUD endpoints exist under `/api/signatures` and the frontend provides a basic UI to create/activate/deactivate signatures with versioning metadata in the DB.


