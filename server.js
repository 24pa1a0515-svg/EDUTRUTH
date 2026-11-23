'use strict';
/**
 * EduTruth backend – Student/Mentor college guidance platform.
 * Zero dependencies: only Node.js built-in modules (http, fs, path, crypto).
 * Run:  node server.js     then open  http://localhost:3000
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');
const INDEX_FILE = path.join(__dirname, 'index.html');

// The single Admin account. Never sent to the browser.
const ADMIN_USER = 'Naren';
const ADMIN_PASS = '7392506666';

const ST = { PENDING: 'Pending Approval', VERIFIED: 'Verified', REJECTED: 'Rejected' };
const RQ = { PENDING: 'Pending', ACCEPTED: 'Accepted', REJECTED: 'Rejected' };

class HttpError extends Error {
  constructor(status, message, code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}
const bad = (m, c) => { throw new HttpError(400, m, c); };

/* ------------------------------------------------------------------ */
/* Database (JSON file persisted)                                      */
/* ------------------------------------------------------------------ */
function seedColleges() {
  const mk = (id, name, location, type, stream, rating, fees, courses, facilities, admission, description) =>
    ({ id, name, location, type, stream, rating, fees, courses, facilities, admission, description });
  return [
    mk('c1', 'Andhra University', 'Visakhapatnam, Andhra Pradesh', 'Government', 'Engineering', 4.3, 'Rs. 60,000 / year',
      ['B.Tech CSE', 'B.Tech ECE', 'MBA', 'M.Sc'], ['Central Library', 'Hostels', 'Sports Complex', 'Research Labs'],
      'Admission through AP EAMCET counselling for B.Tech and AU-CET for postgraduate programs.',
      'One of the oldest and most reputed public universities in Andhra Pradesh, known for engineering and science.'),
    mk('c2', 'IIIT Hyderabad', 'Hyderabad, Telangana', 'Government', 'Engineering', 4.7, 'Rs. 3,00,000 / year',
      ['B.Tech CSE', 'M.Tech', 'MS by Research'], ['Innovation Labs', 'Hostels', 'Incubator', 'Gym'],
      'Admission through JEE Main (UGEE) and the institute entrance process.',
      'A research driven institute with a strong focus on computer science, AI and information technology.'),
    mk('c3', 'Osmania Medical College', 'Hyderabad, Telangana', 'Government', 'Medical', 4.4, 'Rs. 45,000 / year',
      ['MBBS', 'MD', 'MS'], ['Teaching Hospital', 'Hostels', 'Library', 'Skill Lab'],
      'Admission through NEET UG and state counselling.',
      'A well established government medical college with excellent clinical training exposure.'),
    mk('c4', 'SRM Institute of Science and Technology', 'Chennai, Tamil Nadu', 'Private', 'Engineering', 4.0, 'Rs. 2,50,000 / year',
      ['B.Tech', 'MBA', 'B.Sc', 'Law'], ['Wi-Fi Campus', 'Hostels', 'Placement Cell', 'Sports'],
      'Admission through SRMJEEE and merit based counselling.',
      'A large private university offering a wide variety of engineering, management and science programs.'),
    mk('c5', 'Loyola College', 'Chennai, Tamil Nadu', 'Private', 'Science', 4.5, 'Rs. 70,000 / year',
      ['B.Sc Physics', 'B.Sc Chemistry', 'B.Com', 'BA'], ['Library', 'Labs', 'Auditorium', 'Hostel'],
      'Admission based on merit of higher secondary marks and the college application process.',
      'A highly regarded arts and science college with strong academics and alumni network.'),
    mk('c6', 'Christ University', 'Bengaluru, Karnataka', 'Private', 'Commerce', 4.2, 'Rs. 1,80,000 / year',
      ['B.Com', 'BBA', 'LLB', 'MBA'], ['Smart Classrooms', 'Library', 'Sports', 'Cafeteria'],
      'Admission via Christ University entrance test and interview.',
      'A popular private university known for commerce, management and law programs.'),
    mk('c7', 'National Law School of India University', 'Bengaluru, Karnataka', 'Government', 'Law', 4.8, 'Rs. 3,50,000 / year',
      ['BA LLB (Hons)', 'LLM'], ['Moot Court', 'Library', 'Hostels'],
      'Admission through CLAT.', 'India\'s top ranked law school with a strong research and moot court culture.'),
    mk('c8', 'Indian Institute of Management Ahmedabad', 'Ahmedabad, Gujarat', 'Government', 'Management', 4.9, 'Rs. 25,00,000 / program',
      ['PGP', 'PhD'], ['Case Rooms', 'Library', 'Hostels', 'Incubator'],
      'Admission through CAT, written ability test and interview.',
      'A world class management institute with exceptional placements.'),
  ];
}

function emptyDb() {
  return { seq: 0, rev: 0, users: [], colleges: seedColleges(), reviews: [], requests: [], messages: [], notifications: [], saved: {} };
}

function loadDb() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const parsed = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      return Object.assign(emptyDb(), parsed);
    }
  } catch (err) {
    console.error('Could not read data.json, starting fresh:', err.message);
  }
  return emptyDb();
}

const db = loadDb();
let saveTimer = null;
function writeNow() {
  try {
    const tmp = DATA_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(db));
    fs.renameSync(tmp, DATA_FILE);
  } catch (e) {
    console.error('Save failed:', e.message);
  }
}
function save(bump) {
  if (bump !== false) db.rev++;
  if (saveTimer) return;
  saveTimer = setTimeout(() => { saveTimer = null; writeNow(); }, 150);
}
function shutdown() { writeNow(); process.exit(0); }
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

const nid = (p) => `${p}${++db.seq}${crypto.randomBytes(3).toString('hex')}`;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */
function hashPw(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return `${salt}:${crypto.scryptSync(pw, salt, 32).toString('hex')}`;
}
function checkPw(pw, stored) {
  const [salt, h] = String(stored || '').split(':');
  if (!salt || !h) return false;
  const a = crypto.scryptSync(pw, salt, 32);
  const b = Buffer.from(h, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function safeEq(a, b) {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}

function str(v, min, max, label) {
  const s = typeof v === 'string' ? v.trim() : '';
  if (s.length === 0 && min > 0) bad(`${label} is required.`);
  if (s.length < min) bad(`${label} must be at least ${min} characters.`);
  if (s.length > max) bad(`${label} is too long (max ${max} characters).`);
  return s;
}
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
function emailOf(v) {
  const e = str(v, 1, 120, 'Email').toLowerCase();
  if (!EMAIL_RE.test(e)) bad('Please enter a valid email address.');
  return e;
}
function phoneOf(v) {
  const p = str(v, 1, 20, 'Phone');
  if (!/^[0-9+\-\s()]+$/.test(p) || p.replace(/\D/g, '').length < 10) bad('Please enter a valid phone number (at least 10 digits).');
  return p;
}

function publicUser(u) {
  const { passwordHash, ...rest } = u; // eslint-disable-line no-unused-vars
  return rest;
}
function mentorCard(u) {
  return { id: u.id, name: u.name, qualification: u.qualification, college: u.college, experience: u.experience, expertise: u.expertise, bio: u.bio };
}
function studentSummary(u) {
  return { id: u.id, name: u.name, college: u.college, course: u.course, year: u.year };
}
function studentFull(u) {
  return { id: u.id, name: u.name, email: u.email, phone: u.phone, college: u.college, course: u.course, year: u.year, interests: u.interests, status: u.status, createdAt: u.createdAt };
}
const userById = (id) => db.users.find((u) => u.id === id);

function notify(userId, message, key) {
  if (key) {
    const ex = db.notifications.find((n) => n.userId === userId && n.key === key && !n.read);
    if (ex) {
      ex.count = (ex.count || 1) + 1;
      ex.time = Date.now();
      ex.message = ex.message.replace(/^\d+ new messages? from/, `${ex.count} new messages from`);
      return;
    }
  }
  const n = { id: nid('n'), userId, message, time: Date.now(), read: false };
  if (key) { n.key = key; n.count = 1; }
  db.notifications.push(n);
}

function avgRating(college) {
  const rs = db.reviews.filter((r) => r.collegeId === college.id);
  if (!rs.length) return { rating: college.rating, reviewCount: 0 };
  const avg = rs.reduce((a, r) => a + r.rating, 0) / rs.length;
  return { rating: Math.round(avg * 10) / 10, reviewCount: rs.length };
}
function collegeSummary(c, uid) {
  const { rating, reviewCount } = avgRating(c);
  return { ...c, rating, reviewCount, saved: !!(uid && (db.saved[uid] || []).includes(c.id)) };
}

/* ------------------------------------------------------------------ */
/* Sessions                                                            */
/* ------------------------------------------------------------------ */
const sessions = new Map(); // token -> { uid, role }
function newSession(uid, role) {
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, { uid, role });
  return token;
}
function dropSessionsOf(uid) {
  for (const [t, s] of sessions) if (s.uid === uid) sessions.delete(t);
}
const adminUser = () => ({ id: 'admin', role: 'admin', name: 'Admin' });

const failures = new Map(); // ip -> {n, t}
function tooMany(ip) {
  const f = failures.get(ip);
  return !!f && Date.now() - f.t < 60000 && f.n >= 8;
}
function noteFailure(ip) {
  const f = failures.get(ip);
  if (!f || Date.now() - f.t >= 60000) failures.set(ip, { n: 1, t: Date.now() });
  else f.n++;
}

/* ------------------------------------------------------------------ */
/* Router                                                              */
/* ------------------------------------------------------------------ */
const routes = [];
function route(method, pattern, roles, handler, opts) {
  const keys = [];
  const re = new RegExp('^' + pattern.replace(/:([a-zA-Z]+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '$');
  routes.push({ method, re, keys, roles, handler, opts: opts || {} });
}

/* ----- Public: auth ------------------------------------------------ */
route('POST', '/api/register', null, ({ body }) => {
  const role = body.role;
  if (role !== 'student' && role !== 'mentor') bad('Only Student and Mentor accounts can be registered.');
  const name = str(body.name, 2, 80, 'Full name');
  const email = emailOf(body.email);
  const password = typeof body.password === 'string' ? body.password : '';
  if (password.length < 6) bad('Password must be at least 6 characters.');
  if (password.length > 100) bad('Password is too long.');
  if (password !== body.confirmPassword) bad('Passwords do not match.', 'PW_MISMATCH');
  const phone = phoneOf(body.phone);
  if (db.users.some((u) => u.email === email)) throw new HttpError(409, 'An account with this email already exists.', 'DUP_EMAIL');

  const user = { id: nid('u'), role, name, email, passwordHash: hashPw(password), phone, status: ST.PENDING, createdAt: Date.now() };
  if (role === 'student') {
    user.college = str(body.college, 2, 120, 'College/University');
    user.course = str(body.course, 2, 80, 'Course');
    user.year = str(body.year, 1, 30, 'Year of study');
    user.interests = str(body.interests, 2, 200, 'Interests');
  } else {
    user.qualification = str(body.qualification, 2, 120, 'Qualification');
    user.college = str(body.college, 2, 120, 'College/University');
    user.experience = str(body.experience, 1, 80, 'Experience');
    user.expertise = str(body.expertise, 2, 160, 'Expertise');
    user.bio = str(body.bio, 10, 600, 'Bio');
  }
  db.users.push(user);
  notify('admin', `New ${role} registration: ${name}`);
  return { message: 'Your account approval request has been sent to Admin.' };
});

route('POST', '/api/login', null, ({ body, ip }) => {
  if (tooMany(ip)) throw new HttpError(429, 'Too many failed attempts. Please wait a minute.');
  const role = body.role;
  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
  const password = typeof body.password === 'string' ? body.password : '';
  if (role !== 'student' && role !== 'mentor') bad('Invalid role.');
  if (!email || !password) bad('Email and password are required.');
  const u = db.users.find((x) => x.email === email && x.role === role);
  if (!u || !checkPw(password, u.passwordHash)) {
    noteFailure(ip);
    throw new HttpError(401, 'Invalid email or password.', 'INVALID_LOGIN');
  }
  if (u.status === ST.PENDING) throw new HttpError(403, 'Your account is waiting for Admin approval.', 'PENDING');
  if (u.status === ST.REJECTED) throw new HttpError(403, 'Your account has been rejected by Admin.', 'REJECTED');
  return { token: newSession(u.id, u.role), user: publicUser(u) };
}, { noSave: true });

route('POST', '/api/admin/login', null, ({ body, ip }) => {
  if (tooMany(ip)) throw new HttpError(429, 'Too many failed attempts. Please wait a minute.');
  const user = typeof body.username === 'string' ? body.username.trim() : '';
  const pass = typeof body.password === 'string' ? body.password : '';
  if (!safeEq(user, ADMIN_USER) || !safeEq(pass, ADMIN_PASS)) {
    noteFailure(ip);
    throw new HttpError(401, 'Invalid Admin credentials.', 'INVALID_ADMIN');
  }
  return { token: newSession('admin', 'admin'), user: adminUser() };
}, { noSave: true });

route('POST', '/api/logout', 'any', ({ token }) => {
  sessions.delete(token);
  return { ok: true };
}, { noSave: true });

route('GET', '/api/me', 'any', ({ user }) => (user.role === 'admin' ? user : publicUser(user)));

route('GET', '/api/poll', 'any', ({ user }) => {
  const out = { rev: db.rev, unread: db.notifications.filter((n) => n.userId === user.id && !n.read).length };
  return out;
});

/* ----- Notifications ----------------------------------------------- */
route('GET', '/api/notifications', 'any', ({ user }) =>
  db.notifications.filter((n) => n.userId === user.id).sort((a, b) => b.time - a.time).map((n) => ({ id: n.id, message: n.message, time: n.time, read: n.read })));

route('POST', '/api/notifications/read', 'any', ({ user }) => {
  db.notifications.forEach((n) => { if (n.userId === user.id) n.read = true; });
  return { ok: true };
}, { quiet: true });

/* ----- Admin -------------------------------------------------------- */
route('GET', '/api/admin/summary', ['admin'], () => ({
  pending: db.users.filter((u) => u.status === ST.PENDING).length,
  students: db.users.filter((u) => u.role === 'student' && u.status === ST.VERIFIED).length,
  mentors: db.users.filter((u) => u.role === 'mentor' && u.status === ST.VERIFIED).length,
  reviews: db.reviews.length,
  notifications: db.notifications.filter((n) => n.userId === 'admin' && !n.read).length,
}));

route('GET', '/api/admin/users', ['admin'], ({ query }) => {
  const scope = query.get('scope');
  let list;
  if (scope === 'approvals') list = db.users.filter((u) => u.status !== ST.VERIFIED);
  else if (scope === 'students') list = db.users.filter((u) => u.role === 'student' && u.status === ST.VERIFIED);
  else if (scope === 'mentors') list = db.users.filter((u) => u.role === 'mentor' && u.status === ST.VERIFIED);
  else bad('Invalid scope.');
  const rank = { [ST.PENDING]: 0, [ST.REJECTED]: 1, [ST.VERIFIED]: 2 };
  return list.slice().sort((a, b) => rank[a.status] - rank[b.status] || b.createdAt - a.createdAt).map(publicUser);
});

function adminTarget(id) {
  const u = userById(id);
  if (!u) throw new HttpError(404, 'Account not found.');
  return u;
}
route('POST', '/api/admin/users/:id/approve', ['admin'], ({ params }) => {
  const u = adminTarget(params.id);
  u.status = ST.VERIFIED;
  notify(u.id, 'Your account has been approved by Admin. You can now log in.');
  return publicUser(u);
});
route('POST', '/api/admin/users/:id/reject', ['admin'], ({ params }) => {
  const u = adminTarget(params.id);
  u.status = ST.REJECTED;
  notify(u.id, 'Your account request has been rejected by Admin.');
  dropSessionsOf(u.id);
  return publicUser(u);
});
route('DELETE', '/api/admin/users/:id', ['admin'], ({ params }) => {
  const u = adminTarget(params.id);
  const reqIds = new Set(db.requests.filter((r) => r.studentId === u.id || r.mentorId === u.id).map((r) => r.id));
  db.users = db.users.filter((x) => x.id !== u.id);
  db.requests = db.requests.filter((r) => !reqIds.has(r.id));
  db.messages = db.messages.filter((m) => !reqIds.has(m.requestId));
  db.reviews = db.reviews.filter((r) => r.studentId !== u.id);
  db.notifications = db.notifications.filter((n) => n.userId !== u.id);
  delete db.saved[u.id];
  dropSessionsOf(u.id);
  return { ok: true };
});

function collegeInput(body) {
  const list = (v, label) => {
    const raw = Array.isArray(v) ? v : String(v || '').split(',');
    const out = raw.map((x) => String(x).trim()).filter(Boolean).slice(0, 20);
    if (!out.length) bad(`${label} is required.`);
    return out;
  };
  const type = body.type;
  if (type !== 'Government' && type !== 'Private') bad('Type must be Government or Private.');
  const rating = Number(body.rating);
  if (!Number.isFinite(rating) || rating < 0 || rating > 5) bad('Rating must be between 0 and 5.');
  return {
    name: str(body.name, 2, 120, 'College name'),
    location: str(body.location, 2, 120, 'Location'),
    type,
    stream: str(body.stream, 2, 40, 'Stream'),
    rating: Math.round(rating * 10) / 10,
    fees: str(body.fees, 1, 60, 'Fees'),
    courses: list(body.courses, 'Courses'),
    facilities: list(body.facilities, 'Facilities'),
    admission: str(body.admission, 5, 400, 'Admission information'),
    description: str(body.description, 10, 800, 'Description'),
  };
}
route('POST', '/api/admin/colleges', ['admin'], ({ body }) => {
  const c = { id: nid('c'), ...collegeInput(body) };
  db.colleges.push(c);
  return c;
});
route('PUT', '/api/admin/colleges/:id', ['admin'], ({ params, body }) => {
  const c = db.colleges.find((x) => x.id === params.id);
  if (!c) throw new HttpError(404, 'College not found.');
  Object.assign(c, collegeInput(body));
  return c;
});
route('DELETE', '/api/admin/colleges/:id', ['admin'], ({ params }) => {
  const c = db.colleges.find((x) => x.id === params.id);
  if (!c) throw new HttpError(404, 'College not found.');
  db.colleges = db.colleges.filter((x) => x.id !== c.id);
  db.reviews = db.reviews.filter((r) => r.collegeId !== c.id);
  Object.keys(db.saved).forEach((k) => { db.saved[k] = db.saved[k].filter((id) => id !== c.id); });
  return { ok: true };
});
route('GET', '/api/admin/colleges', ['admin'], () => db.colleges.map((c) => collegeSummary(c, null)));
route('GET', '/api/admin/reviews', ['admin'], () =>
  db.reviews.slice().sort((a, b) => b.createdAt - a.createdAt).map((r) => {
    const c = db.colleges.find((x) => x.id === r.collegeId);
    return { ...r, collegeName: c ? c.name : 'Deleted college' };
  }));
route('DELETE', '/api/admin/reviews/:id', ['admin'], ({ params }) => {
  const before = db.reviews.length;
  db.reviews = db.reviews.filter((r) => r.id !== params.id);
  if (db.reviews.length === before) throw new HttpError(404, 'Review not found.');
  return { ok: true };
});

/* ----- Colleges (students) ----------------------------------------- */
route('GET', '/api/colleges', ['student'], ({ user, query }) => {
  const q = (query.get('q') || '').trim().toLowerCase();
  const type = query.get('type') || 'All';
  const stream = query.get('stream') || 'All';
  return db.colleges
    .filter((c) => {
      if (type !== 'All' && c.type !== type) return false;
      if (stream !== 'All' && c.stream !== stream) return false;
      if (!q) return true;
      return [c.name, c.location, c.stream, c.type, ...(c.courses || [])].join(' ').toLowerCase().includes(q);
    })
    .map((c) => collegeSummary(c, user.id))
    .sort((a, b) => b.rating - a.rating);
});
route('GET', '/api/streams', ['student', 'admin'], () => ({ streams: Array.from(new Set(db.colleges.map((c) => c.stream))).sort() }));
route('GET', '/api/saved', ['student'], ({ user }) =>
  (db.saved[user.id] || []).map((id) => db.colleges.find((c) => c.id === id)).filter(Boolean).map((c) => collegeSummary(c, user.id)));
route('GET', '/api/colleges/:id', ['student'], ({ user, params }) => {
  const c = db.colleges.find((x) => x.id === params.id);
  if (!c) throw new HttpError(404, 'College not found.');
  const reviews = db.reviews.filter((r) => r.collegeId === c.id).sort((a, b) => b.createdAt - a.createdAt);
  return { ...collegeSummary(c, user.id), reviews };
});
route('POST', '/api/colleges/:id/save', ['student'], ({ user, params }) => {
  const c = db.colleges.find((x) => x.id === params.id);
  if (!c) throw new HttpError(404, 'College not found.');
  const list = db.saved[user.id] || (db.saved[user.id] = []);
  const i = list.indexOf(c.id);
  if (i >= 0) list.splice(i, 1); else list.push(c.id);
  return { saved: i < 0 };
}, { quiet: true });
route('POST', '/api/colleges/:id/reviews', ['student'], ({ user, params, body }) => {
  const c = db.colleges.find((x) => x.id === params.id);
  if (!c) throw new HttpError(404, 'College not found.');
  const rating = Number(body.rating);
  if (!Number.isInteger(rating) || rating < 1 || rating > 5) bad('Please choose a rating from 1 to 5.', 'BAD_RATING');
  const text = str(body.text, 5, 1000, 'Review');
  const r = { id: nid('r'), collegeId: c.id, studentId: user.id, studentName: user.name, rating, text, createdAt: Date.now() };
  db.reviews.push(r);
  return r;
});

/* ----- Mentors & requests ------------------------------------------ */
const activeRequest = (sid, mid) =>
  db.requests.filter((r) => r.studentId === sid && r.mentorId === mid).sort((a, b) => b.createdAt - a.createdAt)[0] || null;

route('GET', '/api/mentors', ['student'], () =>
  db.users.filter((u) => u.role === 'mentor' && u.status === ST.VERIFIED).map(mentorCard));
route('GET', '/api/mentors/:id', ['student'], ({ user, params }) => {
  const m = userById(params.id);
  if (!m || m.role !== 'mentor' || m.status !== ST.VERIFIED) throw new HttpError(404, 'Mentor not found.');
  return { ...mentorCard(m), request: activeRequest(user.id, m.id) };
});

route('POST', '/api/requests', ['student'], ({ user, body }) => {
  const m = userById(body.mentorId);
  if (!m || m.role !== 'mentor' || m.status !== ST.VERIFIED) throw new HttpError(404, 'Only verified mentors can receive requests.');
  const existing = db.requests.filter((r) => r.studentId === user.id && r.mentorId === m.id);
  if (existing.some((r) => r.status === RQ.PENDING || r.status === RQ.ACCEPTED)) {
    throw new HttpError(409, 'You already have a pending or accepted request with this mentor.', 'DUP_REQUEST');
  }
  db.requests = db.requests.filter((r) => !existing.includes(r));
  const r = { id: nid('q'), studentId: user.id, mentorId: m.id, status: RQ.PENDING, createdAt: Date.now(), updatedAt: Date.now() };
  db.requests.push(r);
  notify(m.id, `New mentor request from ${user.name}`);
  return r;
});

route('GET', '/api/requests', ['student', 'mentor'], ({ user }) => {
  const mine = db.requests.filter((r) => (user.role === 'student' ? r.studentId : r.mentorId) === user.id);
  return mine.sort((a, b) => b.createdAt - a.createdAt).map((r) => {
    const other = userById(user.role === 'student' ? r.mentorId : r.studentId);
    const last = db.messages.filter((m) => m.requestId === r.id).slice(-1)[0] || null;
    return {
      ...r,
      other: other ? (user.role === 'student' ? mentorCard(other) : studentSummary(other)) : null,
      lastMessage: last ? { text: last.text, time: last.time } : null,
    };
  });
});

function requestFor(user, id) {
  const r = db.requests.find((x) => x.id === id);
  if (!r || (r.studentId !== user.id && r.mentorId !== user.id)) throw new HttpError(404, 'Request not found.');
  return r;
}
route('GET', '/api/requests/:id', ['student', 'mentor'], ({ user, params }) => {
  const r = requestFor(user, params.id);
  const other = userById(user.role === 'student' ? r.mentorId : r.studentId);
  if (!other) throw new HttpError(404, 'Account no longer exists.');
  return { ...r, other: user.role === 'student' ? mentorCard(other) : studentFull(other) };
});
function decide(status) {
  return ({ user, params }) => {
    const r = requestFor(user, params.id);
    if (r.mentorId !== user.id) throw new HttpError(403, 'Only the mentor can respond to this request.');
    if (r.status !== RQ.PENDING) throw new HttpError(409, `This request is already ${r.status}.`);
    r.status = status;
    r.updatedAt = Date.now();
    notify(r.studentId, status === RQ.ACCEPTED
      ? `${user.name} accepted your mentor request. You can now chat.`
      : `${user.name} rejected your mentor request.`);
    return r;
  };
}
route('POST', '/api/requests/:id/accept', ['mentor'], decide(RQ.ACCEPTED));
route('POST', '/api/requests/:id/reject', ['mentor'], decide(RQ.REJECTED));

/* ----- Chat (person to person only) -------------------------------- */
function chatRequest(user, id) {
  const r = requestFor(user, id);
  if (r.status !== RQ.ACCEPTED) throw new HttpError(403, 'Chat is available only after the mentor accepts the request.', 'CHAT_LOCKED');
  return r;
}
route('GET', '/api/chat/:id', ['student', 'mentor'], ({ user, params, query }) => {
  const r = chatRequest(user, params.id);
  const after = Number(query.get('after')) || 0;
  const other = userById(user.role === 'student' ? r.mentorId : r.studentId);
  const messages = db.messages.filter((m) => m.requestId === r.id && m.n > after);
  db.notifications.forEach((n) => { if (n.userId === user.id && n.key === `chat:${r.id}`) n.read = true; });
  return { requestId: r.id, other: other ? { id: other.id, name: other.name, role: other.role } : null, messages };
}, { noSave: true });
route('POST', '/api/chat/:id', ['student', 'mentor'], ({ user, params, body }) => {
  const r = chatRequest(user, params.id);
  const text = typeof body.text === 'string' ? body.text.trim() : '';
  if (!text) bad('Message cannot be empty.');
  if (text.length > 2000) bad('Message is too long (max 2000 characters).');
  const msg = { id: nid('m'), n: ++db.seq, requestId: r.id, senderId: user.id, text, time: Date.now() };
  db.messages.push(msg);
  const to = user.id === r.studentId ? r.mentorId : r.studentId;
  notify(to, `1 new message from ${user.name}`, `chat:${r.id}`);
  return msg;
});

/* ------------------------------------------------------------------ */
/* HTTP server                                                         */
/* ------------------------------------------------------------------ */
function send(res, status, data, headers) {
  const body = JSON.stringify(data);
  res.writeHead(status, Object.assign({
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  }, headers));
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > 1e6) { reject(new HttpError(413, 'Request too large.')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try {
        const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        resolve(parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {});
      } catch (e) { reject(new HttpError(400, 'Invalid JSON body.')); }
    });
    req.on('error', reject);
  });
}

function authenticate(req) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  const s = token && sessions.get(token);
  if (!s) return null;
  if (s.role === 'admin') return { token, user: adminUser() };
  const u = userById(s.uid);
  if (!u || u.status !== ST.VERIFIED) { sessions.delete(token); return null; }
  return { token, user: u };
}

async function handleApi(req, res, url) {
  const ip = req.socket.remoteAddress || 'x';
  const r = routes.find((x) => x.method === req.method && x.re.test(url.pathname));
  if (!r) {
    const pathMatch = routes.some((x) => x.re.test(url.pathname));
    throw new HttpError(pathMatch ? 405 : 404, pathMatch ? 'Method not allowed.' : 'Not found.');
  }
  let auth = null;
  if (r.roles) {
    auth = authenticate(req);
    if (!auth) throw new HttpError(401, 'Please log in.', 'AUTH');
    if (Array.isArray(r.roles) && !r.roles.includes(auth.user.role)) throw new HttpError(403, 'You do not have access to this resource.', 'FORBIDDEN');
  }
  const body = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) ? await readBody(req) : {};
  const m = r.re.exec(url.pathname);
  const params = {};
  r.keys.forEach((k, i) => { params[k] = decodeURIComponent(m[i + 1]); });
  const result = await r.handler({ req, ip, body, params, query: url.searchParams, user: auth && auth.user, token: auth && auth.token });
  if (req.method !== 'GET' && !r.opts.noSave) save(!r.opts.quiet);
  send(res, 200, result === undefined ? { ok: true } : result);
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname.startsWith('/api/')) {
      await handleApi(req, res, url);
      return;
    }
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      let html;
      try { html = fs.readFileSync(INDEX_FILE); } catch (e) {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('index.html not found next to server.js');
        return;
      }
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer',
      });
      res.end(html);
      return;
    }
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not found');
  } catch (e) {
    if (res.headersSent) { res.end(); return; }
    if (e instanceof HttpError) { send(res, e.status, { error: e.message, code: e.code }); return; }
    console.error('Unhandled error:', e);
    send(res, 500, { error: 'Internal server error.' });
  }
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') console.error(`Port ${PORT} is already in use. Run with another port, e.g.  PORT=3001 node server.js`);
  else console.error('Server error:', err.message);
  process.exit(1);
});

server.listen(PORT, () => {
  console.log(`EduTruth is running →  http://localhost:${PORT}`);
});
