// Simple seeding script to populate the SQLite DB with example signatures and alerts
const db = require('./db')

const signatures = [
  { name: 'SYN-Flood', desc: 'Detects SYN flood behavior' },
  { name: 'Port-Scan', desc: 'Detects sequential port probes' },
  { name: 'Brute-Auth', desc: 'Detects many failed auth attempts' },
  { name: 'Brave Browser', desc: 'Detects Brave browser process or connections' },
  { name: 'WhatsApp', desc: 'Detects WhatsApp desktop app or whatsapp.com connections' },
  { name: 'YouTube', desc: 'Detects connections to youtube.com or youtu.be' },
  { name: 'LeetCode', desc: 'Detects connections to leetcode.com' },
  { name: 'GeeksforGeeks', desc: 'Detects connections to geeksforgeeks.org / geeksforgeeks.com' }
]

const alerts = [
  { id: 'demo-1', type: 'Port-Scan', severity: 'medium', description: 'Multiple ports probed', time: new Date().toISOString(), src: '192.168.1.50', dst: '10.0.0.10' },
  { id: 'demo-2', type: 'DDoS', severity: 'high', description: 'High SYN rate', time: new Date().toISOString(), src: '10.1.1.5', dst: '10.0.0.10' }
]

function seed() {
  signatures.forEach((s) => db.insertSignature(s, (err) => { if (err) console.error('sig insert', err) }))
  alerts.forEach((a) => db.insertAlert(a, (err) => { if (err) console.error('alert insert', err) }))
  console.log('Seeded demo signatures and alerts')
}

seed()
