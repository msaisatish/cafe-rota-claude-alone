// Small helpers: passwords, dates and HTML.
const crypto = require('crypto');

// ---- Passwords ----
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function checkPassword(password, stored) {
  const [salt, hash] = String(stored).split(':');
  if (!salt || !hash) return false;
  const test = crypto.scryptSync(password, salt, 64);
  const known = Buffer.from(hash, 'hex');
  return known.length === test.length && crypto.timingSafeEqual(known, test);
}

// ---- Dates (always 'YYYY-MM-DD' strings, weeks start on Monday) ----
const pad = (n) => String(n).padStart(2, '0');

function todayISO() {
  const d = new Date();
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

function nowTime() {
  const d = new Date();
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function isISODate(s) {
  if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(s + 'T00:00:00Z');
  return !isNaN(d) && d.toISOString().slice(0, 10) === s;
}

function isTime(s) {
  return typeof s === 'string' && /^([01]\d|2[0-3]):[0-5]\d$/.test(s);
}

function addDays(iso, n) {
  const d = new Date(iso + 'T00:00:00Z');
  d.setUTCDate(d.getUTCDate() + n);
  return d.toISOString().slice(0, 10);
}

function mondayOf(iso) {
  const d = new Date(iso + 'T00:00:00Z');
  return addDays(iso, -((d.getUTCDay() + 6) % 7));
}

function weekDays(monday) {
  return [0, 1, 2, 3, 4, 5, 6].map((i) => addDays(monday, i));
}

function fmtDay(iso, opts = { weekday: 'long', day: 'numeric', month: 'long' }) {
  return new Date(iso + 'T00:00:00Z').toLocaleDateString('en-GB', { ...opts, timeZone: 'UTC' });
}

function fmtShort(iso) {
  return fmtDay(iso, { weekday: 'short', day: 'numeric', month: 'short' });
}

// ---- HTML ----
function h(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function options(items, selected) {
  return items
    .map(([value, label]) => `<option value="${h(value)}"${String(value) === String(selected) ? ' selected' : ''}>${h(label)}</option>`)
    .join('');
}

module.exports = {
  hashPassword, checkPassword,
  todayISO, nowTime, isISODate, isTime, addDays, mondayOf, weekDays, fmtDay, fmtShort,
  h, options,
};
