const crypto = require('crypto');
const path = require('path');
const express = require('express');
const { db, transaction } = require('./db');
const {
  hashPassword, checkPassword,
  todayISO, nowTime, isISODate, isTime, addDays, mondayOf, weekDays, fmtDay, fmtShort,
  h, options,
} = require('./lib');

const PORT = Number(process.env.PORT) || 3000;
const SESSION_DAYS = 30;
const MIN_PASSWORD = 8;
const MIN_STARTING_PASSWORD = 6;

const app = express();
app.disable('x-powered-by');
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// Cookies, sessions and flash messages
// ---------------------------------------------------------------------------

function parseCookies(header) {
  const out = {};
  for (const part of (header || '').split(';')) {
    const i = part.indexOf('=');
    if (i < 1) continue;
    try {
      out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
    } catch { /* ignore malformed cookie */ }
  }
  return out;
}

const cookieBase = { httpOnly: true, sameSite: 'lax', path: '/' };

function startSession(res, userId) {
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare(`INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, datetime('now', ?))`)
    .run(token, userId, `+${SESSION_DAYS} days`);
  res.cookie('sid', token, { ...cookieBase, maxAge: SESSION_DAYS * 86400 * 1000 });
}

function flash(res, message, kind = 'ok') {
  res.cookie('flash', JSON.stringify({ message, kind }), { ...cookieBase, maxAge: 60 * 1000 });
}

app.use((req, res, next) => {
  req.cookies = parseCookies(req.headers.cookie);
  req.user = null;
  if (req.cookies.sid) {
    req.user = db.prepare(`
      SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token = ? AND s.expires_at > datetime('now') AND u.active = 1
    `).get(req.cookies.sid) || null;
  }
  // Someone on a starting password must choose their own before doing anything else.
  if (req.user && req.user.must_change_password && !['/change-password', '/logout'].includes(req.path)) {
    return res.redirect('/change-password');
  }
  next();
});

function requireLogin(req, res, next) {
  if (!req.user) return res.redirect('/login');
  next();
}
function requireManager(req, res, next) {
  if (!req.user) return res.redirect('/login');
  if (req.user.role !== 'manager') return res.redirect('/');
  next();
}
function requireStaff(req, res, next) {
  if (!req.user) return res.redirect('/login');
  if (req.user.role !== 'staff') return res.redirect('/');
  next();
}

// ---------------------------------------------------------------------------
// Page layout
// ---------------------------------------------------------------------------

function render(req, res, title, body, status = 200) {
  let flashHtml = '';
  if (req.cookies.flash) {
    try {
      const f = JSON.parse(req.cookies.flash);
      flashHtml = `<div class="flash flash-${f.kind === 'error' ? 'error' : 'ok'}">${h(f.message)}</div>`;
    } catch { /* ignore */ }
    res.clearCookie('flash', cookieBase);
  }

  let nav = '';
  const u = req.user;
  if (u && !u.must_change_password) {
    const links = u.role === 'manager'
      ? [['/plan', 'Plan the week'], ['/staff', 'Staff'], ['/swaps', `Swap requests${pendingSwapBadge()}`]]
      : [['/my-shifts', 'My shifts'], ['/change-password', 'Password']];
    nav = `<nav>${links.map(([href, label]) =>
      `<a href="${href}"${req.path.startsWith(href) ? ' class="current"' : ''}>${label}</a>`).join('')}
      <form method="post" action="/logout" class="inline"><button class="link">Sign out</button></form></nav>`;
  }

  res.status(status).send(`<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${h(title)} · Café rota</title>
<link rel="stylesheet" href="/style.css">
</head><body>
<header><div class="wrap"><a href="/" class="brand">☕ Café rota</a>${u ? `<span class="who">${h(u.name)}</span>` : ''}</div>
${nav ? `<div class="wrap">${nav}</div>` : ''}</header>
<main class="wrap">${flashHtml}<h1>${h(title)}</h1>${body}</main>
</body></html>`);
}

function pendingSwapBadge() {
  const n = db.prepare(`SELECT COUNT(*) AS n FROM swap_requests WHERE status = 'pending'`).get().n;
  return n ? ` <span class="badge">${n}</span>` : '';
}

const confirmJs = (msg) => `onsubmit="return confirm(${h(JSON.stringify(msg))})"`;

// ---------------------------------------------------------------------------
// Shared queries
// ---------------------------------------------------------------------------

const activeStaff = () =>
  db.prepare(`SELECT id, name, email, must_change_password FROM users WHERE role = 'staff' AND active = 1 ORDER BY name`).all();

const isPublished = (monday) =>
  !!db.prepare(`SELECT 1 FROM weeks WHERE start_date = ? AND published_at IS NOT NULL`).get(monday);

// Shifts that person already has on that day overlapping the given times.
function overlapping(userId, date, start, end, exceptShiftId = 0) {
  return db.prepare(`
    SELECT * FROM shifts WHERE user_id = ? AND date = ? AND id != ?
      AND start_time < ? AND end_time > ?
  `).all(userId, date, exceptShiftId, end, start);
}

// ---------------------------------------------------------------------------
// Home, first-time setup, sign in / out, passwords
// ---------------------------------------------------------------------------

const hasAnyManager = () => !!db.prepare(`SELECT 1 FROM users WHERE role = 'manager'`).get();

app.get('/', (req, res) => {
  if (!hasAnyManager()) return res.redirect('/setup');
  if (!req.user) return res.redirect('/login');
  res.redirect(req.user.role === 'manager' ? '/plan' : '/my-shifts');
});

app.get('/setup', (req, res) => {
  if (hasAnyManager()) return res.redirect('/login');
  render(req, res, 'Welcome — set up the manager account', `
    <p>This is the first time the app has been opened. Create the manager's account. You can add staff afterwards.</p>
    <form method="post" action="/setup" class="card stack">
      <label>Your name <input name="name" required autocomplete="name"></label>
      <label>Email <input name="email" type="email" required autocomplete="email"></label>
      <label>Password (at least ${MIN_PASSWORD} characters)
        <input name="password" type="password" required minlength="${MIN_PASSWORD}" autocomplete="new-password"></label>
      <button>Create manager account</button>
    </form>`);
});

app.post('/setup', (req, res) => {
  if (hasAnyManager()) return res.redirect('/login');
  const name = (req.body.name || '').trim();
  const email = (req.body.email || '').trim().toLowerCase();
  const password = req.body.password || '';
  if (!name || !email.includes('@') || password.length < MIN_PASSWORD) {
    flash(res, `Please fill in every field. The password needs at least ${MIN_PASSWORD} characters.`, 'error');
    return res.redirect('/setup');
  }
  const r = db.prepare(`INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'manager')`)
    .run(name, email, hashPassword(password));
  startSession(res, r.lastInsertRowid);
  flash(res, 'Manager account created. Next, add your staff.');
  res.redirect('/staff');
});

app.get('/login', (req, res) => {
  if (!hasAnyManager()) return res.redirect('/setup');
  if (req.user) return res.redirect('/');
  render(req, res, 'Sign in', `
    <form method="post" action="/login" class="card stack">
      <label>Email <input name="email" type="email" required autocomplete="username" autofocus></label>
      <label>Password <input name="password" type="password" required autocomplete="current-password"></label>
      <button>Sign in</button>
    </form>
    <p class="muted">Forgotten your password? Ask the manager to give you a new starting password.</p>`);
});

app.post('/login', (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const user = db.prepare(`SELECT * FROM users WHERE email = ? AND active = 1`).get(email);
  if (!user || !checkPassword(req.body.password || '', user.password_hash)) {
    flash(res, 'That email and password do not match. Please try again.', 'error');
    return res.redirect('/login');
  }
  startSession(res, user.id);
  res.redirect(user.must_change_password ? '/change-password' : '/');
});

app.post('/logout', (req, res) => {
  if (req.cookies.sid) db.prepare(`DELETE FROM sessions WHERE token = ?`).run(req.cookies.sid);
  res.clearCookie('sid', cookieBase);
  res.redirect('/login');
});

app.get('/change-password', requireLogin, (req, res) => {
  const first = !!req.user.must_change_password;
  render(req, res, first ? 'Choose your own password' : 'Change password', `
    ${first ? `<p>Welcome, ${h(req.user.name)}! You signed in with a starting password. Please choose your own password now.</p>` : ''}
    <form method="post" action="/change-password" class="card stack">
      ${first ? '' : '<label>Current password <input name="current" type="password" required autocomplete="current-password"></label>'}
      <label>New password (at least ${MIN_PASSWORD} characters)
        <input name="password" type="password" required minlength="${MIN_PASSWORD}" autocomplete="new-password"></label>
      <label>New password again <input name="confirm" type="password" required minlength="${MIN_PASSWORD}" autocomplete="new-password"></label>
      <button>Save password</button>
    </form>`);
});

app.post('/change-password', requireLogin, (req, res) => {
  const u = req.user;
  const password = req.body.password || '';
  let error = '';
  if (!u.must_change_password && !checkPassword(req.body.current || '', u.password_hash)) error = 'Your current password is not right.';
  else if (password.length < MIN_PASSWORD) error = `The new password needs at least ${MIN_PASSWORD} characters.`;
  else if (password !== req.body.confirm) error = 'The two new passwords are not the same.';
  else if (checkPassword(password, u.password_hash)) error = 'Please choose a password different from the old one.';
  if (error) {
    flash(res, error, 'error');
    return res.redirect('/change-password');
  }
  transaction(() => {
    db.prepare(`UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?`).run(hashPassword(password), u.id);
    // Sign out any other devices.
    db.prepare(`DELETE FROM sessions WHERE user_id = ? AND token != ?`).run(u.id, req.cookies.sid);
  });
  flash(res, 'Your password has been saved.');
  res.redirect('/');
});

// ---------------------------------------------------------------------------
// Manager: staff
// ---------------------------------------------------------------------------

app.get('/staff', requireManager, (req, res) => {
  const staff = activeStaff();
  const rows = staff.map((s) => `
    <li class="card">
      <div class="row-between">
        <div><strong>${h(s.name)}</strong><br><span class="muted">${h(s.email)}</span>
          ${s.must_change_password ? '<br><span class="tag">Still on starting password</span>' : ''}</div>
        <form method="post" action="/staff/${s.id}/remove" ${confirmJs(`Remove ${s.name}? They will no longer be able to sign in. Any of their shifts still on the rota will be marked for you to reassign.`)}>
          <button class="danger small">Remove</button>
        </form>
      </div>
      <details><summary>Give a new starting password</summary>
        <form method="post" action="/staff/${s.id}/reset" class="inline-form">
          <input name="password" required minlength="${MIN_STARTING_PASSWORD}" placeholder="New starting password" autocomplete="off">
          <button class="small">Set</button>
        </form>
        <p class="muted small-text">Use this if they forget their password. They will be asked to choose their own again.</p>
      </details>
    </li>`).join('');

  render(req, res, 'Staff', `
    <form method="post" action="/staff" class="card stack">
      <h2>Add a staff member</h2>
      <label>Name <input name="name" required autocomplete="off"></label>
      <label>Email <input name="email" type="email" required autocomplete="off"></label>
      <label>Starting password (at least ${MIN_STARTING_PASSWORD} characters)
        <input name="password" required minlength="${MIN_STARTING_PASSWORD}" autocomplete="off"></label>
      <p class="muted small-text">Tell them their email and this password. They will choose their own password the first time they sign in.</p>
      <button>Add staff member</button>
    </form>
    <h2>Current staff (${staff.length})</h2>
    ${staff.length ? `<ul class="list">${rows}</ul>` : '<p class="muted">No staff yet.</p>'}`);
});

app.post('/staff', requireManager, (req, res) => {
  const name = (req.body.name || '').trim();
  const email = (req.body.email || '').trim().toLowerCase();
  const password = req.body.password || '';
  if (!name || !email.includes('@')) {
    flash(res, 'Please give a name and a valid email.', 'error');
    return res.redirect('/staff');
  }
  if (password.length < MIN_STARTING_PASSWORD) {
    flash(res, `The starting password needs at least ${MIN_STARTING_PASSWORD} characters.`, 'error');
    return res.redirect('/staff');
  }
  const existing = db.prepare(`SELECT * FROM users WHERE email = ?`).get(email);
  if (existing && (existing.active || existing.role === 'manager')) {
    flash(res, `Someone with the email ${email} is already set up.`, 'error');
    return res.redirect('/staff');
  }
  if (existing) {
    // A former staff member coming back: reactivate their account.
    db.prepare(`UPDATE users SET name = ?, password_hash = ?, must_change_password = 1, active = 1 WHERE id = ?`)
      .run(name, hashPassword(password), existing.id);
  } else {
    db.prepare(`INSERT INTO users (name, email, password_hash, role, must_change_password) VALUES (?, ?, ?, 'staff', 1)`)
      .run(name, email, hashPassword(password));
  }
  flash(res, `${name} has been added.`);
  res.redirect('/staff');
});

app.post('/staff/:id/remove', requireManager, (req, res) => {
  const s = db.prepare(`SELECT * FROM users WHERE id = ? AND role = 'staff' AND active = 1`).get(req.params.id);
  if (!s) return res.redirect('/staff');
  const upcoming = transaction(() => {
    db.prepare(`UPDATE users SET active = 0 WHERE id = ?`).run(s.id);
    db.prepare(`DELETE FROM sessions WHERE user_id = ?`).run(s.id);
    db.prepare(`UPDATE swap_requests SET status = 'cancelled', decided_at = datetime('now')
                WHERE status = 'pending' AND (from_user_id = ? OR to_user_id = ?)`).run(s.id, s.id);
    return db.prepare(`SELECT COUNT(*) AS n FROM shifts WHERE user_id = ? AND date >= ?`).get(s.id, todayISO()).n;
  });
  flash(res, `${s.name} has been removed.` +
    (upcoming ? ` They still had ${upcoming} upcoming shift${upcoming > 1 ? 's' : ''} — these are marked on the plan for you to reassign.` : ''));
  res.redirect('/staff');
});

app.post('/staff/:id/reset', requireManager, (req, res) => {
  const s = db.prepare(`SELECT * FROM users WHERE id = ? AND role = 'staff' AND active = 1`).get(req.params.id);
  if (!s) return res.redirect('/staff');
  const password = req.body.password || '';
  if (password.length < MIN_STARTING_PASSWORD) {
    flash(res, `The starting password needs at least ${MIN_STARTING_PASSWORD} characters.`, 'error');
    return res.redirect('/staff');
  }
  transaction(() => {
    db.prepare(`UPDATE users SET password_hash = ?, must_change_password = 1 WHERE id = ?`).run(hashPassword(password), s.id);
    db.prepare(`DELETE FROM sessions WHERE user_id = ?`).run(s.id);
  });
  flash(res, `${s.name} has a new starting password. Let them know what it is.`);
  res.redirect('/staff');
});

// ---------------------------------------------------------------------------
// Manager: plan the week
// ---------------------------------------------------------------------------

function weekFrom(value) {
  return mondayOf(isISODate(value) ? value : todayISO());
}

function planUrl(monday, extra = {}) {
  const q = new URLSearchParams({ week: monday, ...extra });
  return `/plan?${q}`;
}

app.get('/plan', requireManager, (req, res) => {
  const monday = weekFrom(req.query.week);
  const days = weekDays(monday);
  const published = isPublished(monday);
  const staff = activeStaff();
  const shifts = db.prepare(`
    SELECT s.*, u.name, u.active FROM shifts s JOIN users u ON u.id = s.user_id
    WHERE s.week_start = ? ORDER BY s.date, s.start_time, u.name
  `).all(monday);
  const pendingByShift = new Set(
    db.prepare(`SELECT shift_id FROM swap_requests WHERE status = 'pending'`).all().map((r) => r.shift_id));
  const prevCount = db.prepare(`SELECT COUNT(*) AS n FROM shifts WHERE week_start = ?`).get(addDays(monday, -7)).n;

  // Remember the last-used day and times so adding several similar shifts is quick.
  const day = days.includes(req.query.day) ? req.query.day : days[0];
  const start = isTime(req.query.start) ? req.query.start : '08:00';
  const end = isTime(req.query.end) ? req.query.end : '14:00';
  const who = req.query.who || '';
  const staffOptions = staff.map((s) => [s.id, s.name]);

  const dayCards = days.map((d) => {
    const list = shifts.filter((s) => s.date === d);
    const items = list.map((s) => `
      <li class="shift${s.active ? '' : ' warn'}">
        <span class="time">${h(s.start_time)}–${h(s.end_time)}</span>
        <form method="post" action="/plan/shifts/${s.id}/assign" class="inline-form grow">
          <select name="user_id" onchange="this.form.submit()" aria-label="Who is working">
            ${s.active ? '' : `<option selected disabled>${h(s.name)} (has left — choose someone)</option>`}
            ${options(staffOptions, s.user_id)}
          </select>
          <noscript><button class="small">Change</button></noscript>
        </form>
        ${pendingByShift.has(s.id) ? '<a href="/swaps" class="tag">swap asked</a>' : ''}
        <form method="post" action="/plan/shifts/${s.id}/delete" class="inline">
          <button class="danger small" title="Delete shift" aria-label="Delete shift">✕</button>
        </form>
      </li>`).join('');
    return `<section class="card day">
      <h3>${h(fmtDay(d))}</h3>
      ${list.length ? `<ul class="shifts">${items}</ul>` : '<p class="muted">No shifts</p>'}
    </section>`;
  }).join('');

  const today = todayISO();
  const thisWeek = mondayOf(today);
  const weekLabel = `Week of ${fmtDay(monday, { day: 'numeric', month: 'long', year: 'numeric' })}`;

  render(req, res, 'Plan the week', `
    <div class="week-nav">
      <a class="button secondary" href="${planUrl(addDays(monday, -7))}">← Previous</a>
      <div class="center"><strong>${h(weekLabel)}</strong>
        ${monday === thisWeek ? '<span class="muted"> (this week)</span>' : ''}<br>
        ${published ? '<span class="tag ok">Published — staff can see it</span>' : '<span class="tag">Draft — staff cannot see it yet</span>'}</div>
      <a class="button secondary" href="${planUrl(addDays(monday, 7))}">Next →</a>
    </div>
    ${monday !== thisWeek ? `<p class="center"><a href="${planUrl(thisWeek)}">Go to this week</a></p>` : ''}

    ${staff.length ? `
    <form method="post" action="/plan/shifts" class="card add-shift">
      <h2>Add a shift</h2>
      <input type="hidden" name="week" value="${h(monday)}">
      <label>Day <select name="date">${options(days.map((d) => [d, fmtShort(d)]), day)}</select></label>
      <label>Start <input type="time" name="start" value="${h(start)}" required></label>
      <label>End <input type="time" name="end" value="${h(end)}" required></label>
      <label>Who <select name="user_id" required><option value="">Choose…</option>${options(staffOptions, who)}</select></label>
      <button>Add shift</button>
    </form>` : `<p class="card">Add your staff on the <a href="/staff">Staff</a> page first, then come back to plan the week.</p>`}

    ${!shifts.length && prevCount ? `
      <form method="post" action="/plan/copy" class="card">
        <input type="hidden" name="week" value="${h(monday)}">
        <p>This week is empty. Start from last week's ${prevCount} shift${prevCount > 1 ? 's' : ''} and adjust?</p>
        <button class="secondary">Copy last week's shifts</button>
      </form>` : ''}

    <div class="days">${dayCards}</div>

    <div class="card publish">
      ${published ? `
        <p>This week is published. Any change you make here is shown to staff straight away.</p>
        <form method="post" action="/plan/unpublish" ${confirmJs('Hide this week from staff again?')}>
          <input type="hidden" name="week" value="${h(monday)}"><button class="secondary">Unpublish (hide from staff)</button></form>`
      : `
        <p>When the week is ready, publish it so staff can see their shifts.</p>
        <form method="post" action="/plan/publish">
          <input type="hidden" name="week" value="${h(monday)}"><button>Publish this week</button></form>`}
    </div>`);
});

app.post('/plan/shifts', requireManager, (req, res) => {
  const monday = weekFrom(req.body.week);
  const { date, start, end } = req.body;
  const back = planUrl(monday, isISODate(date) && isTime(start) && isTime(end) ? { day: date, start, end } : {});
  const person = db.prepare(`SELECT * FROM users WHERE id = ? AND role = 'staff' AND active = 1`).get(req.body.user_id);
  let error = '';
  if (!isISODate(date) || mondayOf(date) !== monday) error = 'Please choose a day in this week.';
  else if (!isTime(start) || !isTime(end)) error = 'Please give a start and end time.';
  else if (end <= start) error = 'The end time must be after the start time.';
  else if (!person) error = 'Please choose who is working.';
  else if (overlapping(person.id, date, start, end).length) error = `${person.name} already has a shift that overlaps those times.`;
  if (error) {
    flash(res, error, 'error');
    // Keep the chosen person so the manager only has to fix what was wrong.
    return res.redirect(person ? `${back}&who=${person.id}` : back);
  }
  db.prepare(`INSERT INTO shifts (week_start, date, start_time, end_time, user_id) VALUES (?, ?, ?, ?, ?)`)
    .run(monday, date, start, end, person.id);
  flash(res, `Added ${person.name}, ${fmtShort(date)} ${start}–${end}.`);
  res.redirect(back);
});

app.post('/plan/shifts/:id/assign', requireManager, (req, res) => {
  const shift = db.prepare(`SELECT * FROM shifts WHERE id = ?`).get(req.params.id);
  if (!shift) return res.redirect('/plan');
  const back = planUrl(shift.week_start);
  const person = db.prepare(`SELECT * FROM users WHERE id = ? AND role = 'staff' AND active = 1`).get(req.body.user_id);
  if (!person) return res.redirect(back);
  if (person.id === shift.user_id) return res.redirect(back);
  if (overlapping(person.id, shift.date, shift.start_time, shift.end_time, shift.id).length) {
    flash(res, `${person.name} already has a shift that overlaps those times.`, 'error');
    return res.redirect(back);
  }
  transaction(() => {
    db.prepare(`UPDATE shifts SET user_id = ? WHERE id = ?`).run(person.id, shift.id);
    // Any swap asked for this shift no longer makes sense.
    db.prepare(`UPDATE swap_requests SET status = 'cancelled', decided_at = datetime('now')
                WHERE shift_id = ? AND status = 'pending'`).run(shift.id);
  });
  flash(res, `${fmtShort(shift.date)} ${shift.start_time}–${shift.end_time} is now ${person.name}'s shift.`);
  res.redirect(back);
});

app.post('/plan/shifts/:id/delete', requireManager, (req, res) => {
  const shift = db.prepare(`SELECT * FROM shifts WHERE id = ?`).get(req.params.id);
  if (!shift) return res.redirect('/plan');
  db.prepare(`DELETE FROM shifts WHERE id = ?`).run(shift.id);
  flash(res, `Deleted the shift on ${fmtShort(shift.date)} ${shift.start_time}–${shift.end_time}.`);
  res.redirect(planUrl(shift.week_start));
});

app.post('/plan/copy', requireManager, (req, res) => {
  const monday = weekFrom(req.body.week);
  const copied = transaction(() => {
    if (db.prepare(`SELECT 1 FROM shifts WHERE week_start = ?`).get(monday)) return -1;
    const prev = db.prepare(`
      SELECT s.* FROM shifts s JOIN users u ON u.id = s.user_id
      WHERE s.week_start = ? AND u.active = 1
    `).all(addDays(monday, -7));
    const insert = db.prepare(`INSERT INTO shifts (week_start, date, start_time, end_time, user_id) VALUES (?, ?, ?, ?, ?)`);
    for (const s of prev) insert.run(monday, addDays(s.date, 7), s.start_time, s.end_time, s.user_id);
    return prev.length;
  });
  if (copied >= 0) flash(res, `Copied ${copied} shift${copied === 1 ? '' : 's'} from last week. Nothing is published until you press Publish.`);
  res.redirect(planUrl(monday));
});

app.post('/plan/publish', requireManager, (req, res) => {
  const monday = weekFrom(req.body.week);
  db.prepare(`INSERT INTO weeks (start_date, published_at) VALUES (?, datetime('now'))
              ON CONFLICT(start_date) DO UPDATE SET published_at = datetime('now')`).run(monday);
  flash(res, 'Week published. Staff can now see their shifts.');
  res.redirect(planUrl(monday));
});

app.post('/plan/unpublish', requireManager, (req, res) => {
  const monday = weekFrom(req.body.week);
  db.prepare(`UPDATE weeks SET published_at = NULL WHERE start_date = ?`).run(monday);
  flash(res, 'Week hidden from staff.');
  res.redirect(planUrl(monday));
});

// ---------------------------------------------------------------------------
// Staff: my shifts and asking for a swap
// ---------------------------------------------------------------------------

app.get('/my-shifts', requireStaff, (req, res) => {
  const me = req.user;
  const today = todayISO();
  const shifts = db.prepare(`
    SELECT s.* FROM shifts s JOIN weeks w ON w.start_date = s.week_start AND w.published_at IS NOT NULL
    WHERE s.user_id = ? AND (s.date > ? OR (s.date = ? AND s.end_time > ?))
    ORDER BY s.date, s.start_time
  `).all(me.id, today, today, nowTime());
  const pending = new Map(db.prepare(`
    SELECT r.id, r.shift_id, u.name AS to_name FROM swap_requests r JOIN users u ON u.id = r.to_user_id
    WHERE r.from_user_id = ? AND r.status = 'pending'
  `).all(me.id).map((r) => [r.shift_id, r]));
  const colleagues = activeStaff().filter((s) => s.id !== me.id).map((s) => [s.id, s.name]);

  const cards = shifts.map((s) => {
    const p = pending.get(s.id);
    return `<li class="card my-shift${s.date === today ? ' today' : ''}">
      <div class="row-between">
        <div><strong>${h(fmtDay(s.date))}</strong>${s.date === today ? ' <span class="tag ok">Today</span>' : ''}<br>
          <span class="big">${h(s.start_time)}–${h(s.end_time)}</span></div>
      </div>
      ${p ? `
        <div class="row-between pending">
          <span>Swap with <strong>${h(p.to_name)}</strong> asked — waiting for the manager.</span>
          <form method="post" action="/swaps/${p.id}/cancel" class="inline"><button class="secondary small">Cancel request</button></form>
        </div>`
      : colleagues.length ? `
        <details><summary class="button secondary small">Ask to swap</summary>
          <form method="post" action="/swaps" class="stack">
            <input type="hidden" name="shift_id" value="${s.id}">
            <label>Who would take this shift? <select name="to_user_id" required><option value="">Choose…</option>${options(colleagues, '')}</select></label>
            <label>Message for the manager (optional) <input name="note" maxlength="200" placeholder="e.g. Sam has agreed"></label>
            <button>Send swap request</button>
          </form>
        </details>` : ''}
    </li>`;
  }).join('');

  const history = db.prepare(`
    SELECT r.*, s.date, s.start_time, s.end_time, u.name AS to_name FROM swap_requests r
    JOIN shifts s ON s.id = r.shift_id JOIN users u ON u.id = r.to_user_id
    WHERE r.from_user_id = ? AND r.status != 'pending'
    ORDER BY r.decided_at DESC LIMIT 5
  `).all(me.id);
  const askedOfMe = db.prepare(`
    SELECT r.*, s.date, s.start_time, s.end_time, u.name AS from_name FROM swap_requests r
    JOIN shifts s ON s.id = r.shift_id JOIN users u ON u.id = r.from_user_id
    WHERE r.to_user_id = ? AND r.status = 'pending' ORDER BY s.date, s.start_time
  `).all(me.id);
  const statusText = { approved: 'Approved', declined: 'Turned down', cancelled: 'Cancelled' };

  render(req, res, 'My shifts', `
    ${shifts.length ? `<ul class="list">${cards}</ul>`
      : '<p class="card">You have no upcoming shifts on a published rota. The manager will publish the next week soon.</p>'}
    ${askedOfMe.length ? `<h2>Colleagues asking you to take a shift</h2><ul class="list">${askedOfMe.map((r) => `
      <li class="card">${h(r.from_name)} has asked for you to take <strong>${h(fmtShort(r.date))} ${h(r.start_time)}–${h(r.end_time)}</strong>.
      It becomes your shift if the manager approves.</li>`).join('')}</ul>` : ''}
    ${history.length ? `<h2>Recent swap requests</h2><ul class="list">${history.map((r) => `
      <li class="card">${h(fmtShort(r.date))} ${h(r.start_time)}–${h(r.end_time)} → ${h(r.to_name)}:
        <span class="tag ${r.status === 'approved' ? 'ok' : ''}">${statusText[r.status]}</span></li>`).join('')}</ul>` : ''}`);
});

app.post('/swaps', requireStaff, (req, res) => {
  const me = req.user;
  const today = todayISO();
  const shift = db.prepare(`
    SELECT s.* FROM shifts s JOIN weeks w ON w.start_date = s.week_start AND w.published_at IS NOT NULL
    WHERE s.id = ? AND s.user_id = ? AND s.date >= ?
  `).get(req.body.shift_id, me.id, today);
  const to = db.prepare(`SELECT * FROM users WHERE id = ? AND role = 'staff' AND active = 1 AND id != ?`)
    .get(req.body.to_user_id, me.id);
  const note = (req.body.note || '').trim().slice(0, 200);
  let error = '';
  if (!shift) error = 'That shift could not be found.';
  else if (!to) error = 'Please choose a colleague.';
  else if (db.prepare(`SELECT 1 FROM swap_requests WHERE shift_id = ? AND status = 'pending'`).get(shift.id))
    error = 'You have already asked to swap that shift.';
  if (error) {
    flash(res, error, 'error');
    return res.redirect('/my-shifts');
  }
  db.prepare(`INSERT INTO swap_requests (shift_id, from_user_id, to_user_id, note) VALUES (?, ?, ?, ?)`)
    .run(shift.id, me.id, to.id, note);
  flash(res, `Swap request sent. Until the manager approves it, the shift is still yours.`);
  res.redirect('/my-shifts');
});

app.post('/swaps/:id/cancel', requireStaff, (req, res) => {
  db.prepare(`UPDATE swap_requests SET status = 'cancelled', decided_at = datetime('now')
              WHERE id = ? AND from_user_id = ? AND status = 'pending'`).run(req.params.id, req.user.id);
  flash(res, 'Swap request cancelled.');
  res.redirect('/my-shifts');
});

// ---------------------------------------------------------------------------
// Manager: swap requests
// ---------------------------------------------------------------------------

app.get('/swaps', requireManager, (req, res) => {
  const pending = db.prepare(`
    SELECT r.*, s.date, s.start_time, s.end_time, s.user_id AS shift_user,
           f.name AS from_name, t.name AS to_name, t.active AS to_active
    FROM swap_requests r JOIN shifts s ON s.id = r.shift_id
    JOIN users f ON f.id = r.from_user_id JOIN users t ON t.id = r.to_user_id
    WHERE r.status = 'pending' ORDER BY s.date, s.start_time
  `).all();
  const recent = db.prepare(`
    SELECT r.*, s.date, s.start_time, s.end_time, f.name AS from_name, t.name AS to_name
    FROM swap_requests r JOIN shifts s ON s.id = r.shift_id
    JOIN users f ON f.id = r.from_user_id JOIN users t ON t.id = r.to_user_id
    WHERE r.status != 'pending' ORDER BY r.decided_at DESC LIMIT 15
  `).all();
  const statusText = { approved: 'Approved', declined: 'Turned down', cancelled: 'Cancelled' };

  const cards = pending.map((r) => {
    const clash = overlapping(r.to_user_id, r.date, r.start_time, r.end_time, r.shift_id);
    return `<li class="card">
      <p><strong>${h(r.from_name)}</strong> asks for <strong>${h(r.to_name)}</strong> to take
        <strong>${h(fmtDay(r.date))}, ${h(r.start_time)}–${h(r.end_time)}</strong>.</p>
      ${r.note ? `<p class="note">“${h(r.note)}”</p>` : ''}
      ${clash.length ? `<p class="warn-text">⚠ ${h(r.to_name)} already works ${clash.map((c) => `${h(c.start_time)}–${h(c.end_time)}`).join(', ')} that day, which overlaps.</p>` : ''}
      <div class="actions">
        <form method="post" action="/swaps/${r.id}/approve" class="inline"><button>Approve</button></form>
        <form method="post" action="/swaps/${r.id}/decline" class="inline"><button class="secondary">Turn down</button></form>
      </div>
    </li>`;
  }).join('');

  render(req, res, 'Swap requests', `
    ${pending.length ? `<ul class="list">${cards}</ul>` : '<p class="card">No swap requests waiting. 👍</p>'}
    ${recent.length ? `<h2>Recently decided</h2><ul class="list compact">${recent.map((r) => `
      <li>${h(fmtShort(r.date))} ${h(r.start_time)}–${h(r.end_time)}: ${h(r.from_name)} → ${h(r.to_name)}
        <span class="tag ${r.status === 'approved' ? 'ok' : ''}">${statusText[r.status]}</span></li>`).join('')}</ul>` : ''}`);
});

app.post('/swaps/:id/approve', requireManager, (req, res) => {
  const r = db.prepare(`
    SELECT r.*, s.user_id AS shift_user, s.date, s.start_time, s.end_time, t.name AS to_name, t.active AS to_active
    FROM swap_requests r JOIN shifts s ON s.id = r.shift_id JOIN users t ON t.id = r.to_user_id
    WHERE r.id = ? AND r.status = 'pending'
  `).get(req.params.id);
  if (!r) return res.redirect('/swaps');
  if (r.shift_user !== r.from_user_id || !r.to_active) {
    db.prepare(`UPDATE swap_requests SET status = 'cancelled', decided_at = datetime('now') WHERE id = ?`).run(r.id);
    flash(res, 'That request no longer applies (the shift or the people have changed), so it has been cancelled.', 'error');
    return res.redirect('/swaps');
  }
  transaction(() => {
    db.prepare(`UPDATE shifts SET user_id = ? WHERE id = ?`).run(r.to_user_id, r.shift_id);
    db.prepare(`UPDATE swap_requests SET status = 'approved', decided_at = datetime('now') WHERE id = ?`).run(r.id);
  });
  flash(res, `Approved. ${fmtShort(r.date)} ${r.start_time}–${r.end_time} is now ${r.to_name}'s shift.`);
  res.redirect('/swaps');
});

app.post('/swaps/:id/decline', requireManager, (req, res) => {
  db.prepare(`UPDATE swap_requests SET status = 'declined', decided_at = datetime('now')
              WHERE id = ? AND status = 'pending'`).run(req.params.id);
  flash(res, 'Request turned down. The rota has not changed.');
  res.redirect('/swaps');
});

// ---------------------------------------------------------------------------

app.use((req, res) => render(req, res, 'Page not found', '<p><a href="/">Go to the start</a></p>', 404));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send('Something went wrong. Please go back and try again.');
});

app.listen(PORT, () => {
  console.log(`Café rota is running. Open http://localhost:${PORT} in your browser.`);
});
