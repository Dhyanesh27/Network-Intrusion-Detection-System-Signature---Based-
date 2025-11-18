// CLI helper to seed signatures into the DB from signatures/signatures.json
const fs = require('fs')
const path = require('path')
const db = require('./db')

async function run() {
  try {
    const sigPath = path.join(__dirname, '..', 'signatures', 'signatures.json')
    if (!fs.existsSync(sigPath)) {
      console.error('signatures.json not found at', sigPath)
      process.exit(2)
    }
    const sigs = JSON.parse(fs.readFileSync(sigPath, 'utf8'))
    db.listSignatures((err, rows) => {
      if (err) {
        console.error('Failed to list signatures:', err)
        process.exit(1)
      }
      const existing = new Set((rows || []).map(r => (r.name || '').toLowerCase()))
      const inserted = []
      sigs.forEach((s) => {
        const name = (s.name || s.id || '').toString()
        if (!name) return
        if (!existing.has(name.toLowerCase())) {
          db.insertSignature({ name, desc: s.description || s.desc || '' }, (ie) => {
            if (ie) console.error('Failed to insert signature', name, ie)
          })
          inserted.push(name)
        }
      })
      console.log('Seed complete. Inserted:', inserted)
      process.exit(0)
    })
  } catch (e) {
    console.error('Failed seeding:', e)
    process.exit(1)
  }
}

run()
