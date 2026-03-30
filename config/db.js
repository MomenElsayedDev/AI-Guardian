/**
 * config/db.js – Simple JSON file-based database
 * Drop-in replacement for MongoDB (no setup required)
 * Swap for Mongoose if MongoDB is preferred.
 */

const fs = require('fs').promises;
const path = require('path');

const DB_PATH = path.join(__dirname, '..', 'data', 'scans.json');

// ─── Ensure data directory & file exist ──────────────────────────────────────
async function ensureDB() {
  const dir = path.dirname(DB_PATH);
  try {
    await fs.mkdir(dir, { recursive: true });
    await fs.access(DB_PATH);
  } catch {
    await fs.writeFile(DB_PATH, JSON.stringify([], null, 2), 'utf8');
  }
}

// ─── Read all records ─────────────────────────────────────────────────────────
async function getAll() {
  await ensureDB();
  const raw = await fs.readFile(DB_PATH, 'utf8');
  const data = JSON.parse(raw);
  // Return newest first
  return data.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
}

// ─── Save a new record ────────────────────────────────────────────────────────
async function save(scan) {
  await ensureDB();
  const raw = await fs.readFile(DB_PATH, 'utf8');
  const data = JSON.parse(raw);
  data.push(scan);
  // Keep last 500 records max
  const trimmed = data.slice(-500);
  await fs.writeFile(DB_PATH, JSON.stringify(trimmed, null, 2), 'utf8');
  return scan;
}

// ─── Delete a record by ID ────────────────────────────────────────────────────
async function remove(id) {
  await ensureDB();
  const raw = await fs.readFile(DB_PATH, 'utf8');
  const data = JSON.parse(raw);
  const index = data.findIndex(s => s.id === id);
  if (index === -1) return null;
  const [deleted] = data.splice(index, 1);
  await fs.writeFile(DB_PATH, JSON.stringify(data, null, 2), 'utf8');
  return deleted;
}

// ─── Find one by ID ───────────────────────────────────────────────────────────
async function findById(id) {
  const data = await getAll();
  return data.find(s => s.id === id) || null;
}

// ─── Clear all (utility) ──────────────────────────────────────────────────────
async function clearAll() {
  await fs.writeFile(DB_PATH, JSON.stringify([], null, 2), 'utf8');
}

module.exports = { getAll, save, remove, findById, clearAll };

/*
 * ──────────────────────────────────────────────
 *  OPTIONAL: MongoDB version with Mongoose
 *  Uncomment and replace exports above to use.
 * ──────────────────────────────────────────────
 *
 * const mongoose = require('mongoose');
 *
 * mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost/ai-guardian')
 *   .then(() => console.log('[DB] MongoDB connected'))
 *   .catch(err => console.error('[DB] Connection error:', err));
 *
 * const ScanSchema = new mongoose.Schema({
 *   id: { type: String, required: true, unique: true },
 *   input: { type: String, required: true },
 *   result: {
 *     status: String,
 *     confidence: Number,
 *     explanation: String,
 *     keywords: [String],
 *   },
 *   timestamp: { type: Date, default: Date.now },
 * });
 *
 * const Scan = mongoose.model('Scan', ScanSchema);
 *
 * async function getAll() {
 *   return Scan.find().sort({ timestamp: -1 }).lean();
 * }
 * async function save(scan) {
 *   return new Scan(scan).save();
 * }
 * async function remove(id) {
 *   return Scan.findOneAndDelete({ id });
 * }
 * async function findById(id) {
 *   return Scan.findOne({ id }).lean();
 * }
 * module.exports = { getAll, save, remove, findById };
 */
