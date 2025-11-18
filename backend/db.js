const sqlite3 = require('sqlite3').verbose()
const path = require('path')

const dbPath = path.join(__dirname, 'nids.db')
const db = new sqlite3.Database(dbPath)

db.serialize(() => {
  // Core tables
  db.run(`CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    type TEXT,
    severity TEXT,
    description TEXT,
    time TEXT,
    src TEXT,
    dst TEXT,
    acknowledged INTEGER DEFAULT 0,
    escalated INTEGER DEFAULT 0,
    notes TEXT
  )`)

  db.run(`CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT,
    message TEXT
  )`)

  db.run(`CREATE TABLE IF NOT EXISTS signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    desc TEXT,
    version INTEGER DEFAULT 1,
    active INTEGER DEFAULT 1,
    created_at TEXT
  )`)

  db.run(`CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT,
    src TEXT,
    src_port INTEGER,
    dst TEXT,
    dst_port INTEGER,
    proto TEXT,
    size INTEGER,
    pid INTEGER,
    proc_name TEXT,
    raw TEXT
  )`)
})

// --- Alert Operations ---
function insertAlert(a, cb) {
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO alerts (id, type, severity, description, time, src, dst)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `)
  stmt.run(
    a.id || `${Date.now()}-${Math.random()}`,
    a.type || '',
    a.severity || '',
    a.description || '',
    a.time || new Date().toISOString(),
    a.src || '',
    a.dst || '',
    (err) => {
      stmt.finalize()
      cb && cb(err)
    }
  )
}

function updateAlertTriage(id, { acknowledged, escalated, notes }, cb) {
  db.run(
    `UPDATE alerts SET acknowledged=?, escalated=?, notes=? WHERE id=?`,
    [acknowledged ? 1 : 0, escalated ? 1 : 0, notes || '', id],
    cb
  )
}

// --- Audit Logging ---
function insertAudit(msg, cb) {
  db.run(
    `INSERT INTO audit (time, message) VALUES (?, ?)`,
    [new Date().toISOString(), msg],
    cb
  )
}

// --- Event Insertion ---
function insertEvent(e, cb) {
  const raw = JSON.stringify(e)
  db.run(
    `INSERT INTO events (time, src, src_port, dst, dst_port, proto, size, pid, proc_name, raw)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      e.time || new Date().toISOString(),
      e.src || '',
      e.src_port || null,
      e.dst || '',
      e.dst_port || null,
      e.proto || '',
      e.size || 0,
      e.pid || null,
      e.proc_name || null,
      raw,
    ],
    cb
  )
}

// --- Signatures ---
function insertSignature(s, cb) {
  const now = new Date().toISOString()
  db.run(
    `INSERT INTO signatures (name, desc, version, active, created_at) VALUES (?, ?, ?, ?, ?)`,
    [s.name, s.desc, s.version || 1, s.active ? 1 : 1, now],
    cb
  )
}

// --- Listing Functions ---
const listAlerts = (cb) => db.all(`SELECT * FROM alerts ORDER BY time DESC LIMIT 200`, cb)
const listAudit = (cb) => db.all(`SELECT * FROM audit ORDER BY id DESC LIMIT 200`, cb)
const listSignatures = (cb) => db.all(`SELECT * FROM signatures ORDER BY id`, cb)

const getSignature = (id, cb) => db.get(`SELECT * FROM signatures WHERE id=?`, [id], cb)
const deactivateSignature = (id, cb) => db.run(`UPDATE signatures SET active=0 WHERE id=?`, [id], cb)
const activateSignature = (id, cb) => db.run(`UPDATE signatures SET active=1 WHERE id=?`, [id], cb)

// --- Retention Job ---
function retentionJob(days = 30) {
  const cutoff = new Date(Date.now() - days * 24 * 3600 * 1000).toISOString()
  db.run(`DELETE FROM alerts WHERE time < ?`, cutoff, (err) => {
    if (err) console.error('Retention job error:', err)
  })
}

// Export for other modules
module.exports = {
  insertAlert,
  insertAudit,
  insertSignature,
  insertEvent,
  updateAlertTriage,
  listAlerts,
  listAudit,
  listSignatures,
  getSignature,
  deactivateSignature,
  activateSignature,
  retentionJob
}
