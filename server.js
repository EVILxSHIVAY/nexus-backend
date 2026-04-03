try { require('dotenv').config(); } catch (_) {}

const express        = require('express');
const { createServer } = require('http');
const { Server }     = require('socket.io');
const { v4: uuidv4 } = require('uuid');
const cors           = require('cors');
const path           = require('path');
const fs             = require('fs');
const session        = require('express-session');
const passport       = require('passport');
const LocalStrategy  = require('passport-local').Strategy;

const app        = express();
const httpServer = createServer(app);

// ── Data files ──────────────────────────────────────────────────────────────
const DATA_DIR      = path.join(__dirname, 'data');
const USERS_FILE    = path.join(DATA_DIR, 'users.json');
const MEETINGS_FILE = path.join(DATA_DIR, 'meetings.json');
const LOGIN_FILE  = path.join(DATA_DIR, 'login.json');
const LOGOUT_FILE = path.join(DATA_DIR, 'logout.json');

if (!fs.existsSync(DATA_DIR))      fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE))    fs.writeFileSync(USERS_FILE,    '[]', 'utf8');
if (!fs.existsSync(MEETINGS_FILE)) fs.writeFileSync(MEETINGS_FILE, '[]', 'utf8');
if (!fs.existsSync(LOGIN_FILE))  fs.writeFileSync(LOGIN_FILE,  '[]', 'utf8');
if (!fs.existsSync(LOGOUT_FILE)) fs.writeFileSync(LOGOUT_FILE, '[]', 'utf8');

// ── File helpers ─────────────────────────────────────────────────────────────
const readUsers    = () => { try { return JSON.parse(fs.readFileSync(USERS_FILE,    'utf8')); } catch(_){ return []; } };
const writeUsers   = u  => fs.writeFileSync(USERS_FILE,    JSON.stringify(u, null, 2), 'utf8');
const readMeetings = () => { try { return JSON.parse(fs.readFileSync(MEETINGS_FILE, 'utf8')); } catch(_){ return []; } };
const writeMeetings= m  => fs.writeFileSync(MEETINGS_FILE, JSON.stringify(m, null, 2), 'utf8');
const readLogin  = () => JSON.parse(fs.readFileSync(LOGIN_FILE, 'utf8') || '[]');
const writeLogin = d  => fs.writeFileSync(LOGIN_FILE, JSON.stringify(d, null, 2));

const readLogout  = () => JSON.parse(fs.readFileSync(LOGOUT_FILE, 'utf8') || '[]');
const writeLogout = d  => fs.writeFileSync(LOGOUT_FILE, JSON.stringify(d, null, 2));

const findUserById      = id    => readUsers().find(u => u.id === id);
const findUserByEmail   = email => readUsers().find(u => u.email?.toLowerCase() === email?.toLowerCase());

const genRoomId = () => {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  return Array.from({ length: 8 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
};

// 🔥 TRUST PROXY (IMPORTANT FOR RENDER)
app.set('trust proxy', 1);

// 🔥 CORS FIX (allow cookies)

const corsOptions = {
  origin: "https://nexus-frontend-z4o5.vercel.app",
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
// ── Session ──────────────────────────────────────────────────────────────────
const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || 'nexus-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,        // 🔥 IMPORTANT (Render fix)
    httpOnly: true,
    sameSite: 'lax',      // 🔥 REQUIRED
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
});

app.use(sessionMiddleware);

// ── Passport ─────────────────────────────────────────────────────────────────
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => done(null, findUserById(id) || false));

passport.use(new LocalStrategy(
  { usernameField: 'email', passwordField: 'password' },
  (email, password, done) => {
    const user = findUserByEmail(email);

    if (!user) {
      return done(null, false, { message: 'No account found' });
    }

    if (user.password !== password) {
      return done(null, false, { message: 'Incorrect password' });
    }

    return done(null, user);
  }
));

// ── Express middleware ────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(sessionMiddleware);
app.use(passport.initialize());
app.use(passport.session());

// Serve static assets but NOT html directly
app.use('/css',  express.static(path.join(__dirname, 'public', 'css')));
app.use('/js',   express.static(path.join(__dirname, 'public', 'js')));

// ── Auth guard ────────────────────────────────────────────────────────────────
const requireAuth = (req, res, next) => {
  if (req.isAuthenticated()) return next();
  req.session.returnTo = req.originalUrl;
  res.redirect('/login');
};

// ── Socket.IO ─────────────────────────────────────────────────────────────────
const io = new Server(httpServer, {
  cors: {
    origin: "https://nexus-frontend-z4o5.vercel.app",
    methods: ["GET", "POST"],
    credentials: true
  },
  transports: ['websocket', 'polling']
});

io.use((socket, next) => sessionMiddleware(socket.request, {}, next));

app.get('/api/logout', (req, res) => {
  req.logout(() => {
    req.session.destroy();
    res.json({ success: true });
  });
});

// ── Auth API ──────────────────────────────────────────────────────────────────
app.post('/api/auth/signup', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: 'Name, email and password are required.' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  if (findUserByEmail(email))
    return res.status(400).json({ error: 'An account with this email already exists.' });

  const newUser = {
    id: uuidv4(),
    name: name.trim().substring(0, 50),
    email: email.toLowerCase().trim(),
    password,
    createdAt: new Date().toLocaleDateString('en-GB', {
      day: '2-digit',
      month: 'short',
      year: 'numeric'
    })
  };
  const users = readUsers();
  users.push(newUser);
  writeUsers(users);

  req.login(newUser, err => {
    if (err) return res.status(500).json({ error: 'Signup succeeded but login failed.' });
    const { password, ...safe } = newUser;
    res.json({ success: true, user: safe });
  });
});

app.post('/api/auth/login', (req, res, next) => {
  const { email, password } = req.body;

  const users = readUsers();
  const user = users.find(u => u.email === email);

  if (!user || user.password !== password) {
    return res.status(401).json({ message: "Invalid email or password" });
  }

  req.login(user, (err) => {
    if (err) return next(err);

    res.json({ message: "Login successful", user });
  });
});

app.get('/api/me', requireAuth, (req, res) => {
  const { password, ...safe } = req.user; // remove password
  res.json(safe);
});

app.put('/api/me', requireAuth, (req, res) => {
  const { name } = req.body;

  if (!name?.trim()) {
    return res.status(400).json({ error: 'Name is required.' });
  }

  const users = readUsers();
  const idx = users.findIndex(u => u.id === req.user.id);

  if (idx === -1) {
    return res.status(404).json({ error: 'User not found.' });
  }

  users[idx].name = name.trim().substring(0, 50);
  users[idx].initial = name.trim().charAt(0).toUpperCase();

  writeUsers(users);

  const { password, ...safe } = users[idx]; // remove password

  req.login(users[idx], () => res.json(safe));
});

// ── Meetings API ──────────────────────────────────────────────────────────────
app.get('/api/meetings', requireAuth, (req, res) => {
  const mine = readMeetings()
    .filter(m => m.hostId === req.user.id || m.participants?.some(p => p.userId === req.user.id))
    .sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt));
  res.json(mine);
});

app.post('/api/meetings/create', requireAuth, (req, res) => {
  const roomId  = genRoomId();
  const meeting = {
  id: uuidv4(),
  roomId,
  title: req.body.title?.trim() || `Meeting ${roomId}`,

  host: {
    id: req.user.id,
    name: req.user.name
  },

  participants: [{
  userId: req.user.id,
  name: req.user.name,
  joinedAt: new Date().toISOString()
}],

  startedAt: new Date().toISOString()

};
  const meetings = readMeetings();
  meetings.push(meeting);
  writeMeetings(meetings);
  res.json({ roomId, meetingId: meeting.id });
});

// ── Health ────────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({
  status: 'ok', rooms: rooms.size,
  users: readUsers().length, meetings: readMeetings().length, uptime: process.uptime()
}));

app.get('/api/rooms/:roomId', (req, res) => {
  const room = rooms.get(req.params.roomId);
  if (!room) return res.status(404).json({ error: 'Room not found' });
  res.json({ roomId: room.id, peerCount: room.peers.size,
    peers: Array.from(room.peers.values()).map(p => ({ socketId: p.socketId, name: p.name })) });
});

// ── Room store ────────────────────────────────────────────────────────────────
const rooms = new Map();

const createRoom = roomId => {
  const room = { id: roomId, createdAt: Date.now(), peers: new Map() };
  rooms.set(roomId, room);
  return room;
};

const cleanupEmptyRooms = () => {
  for (const [id, room] of rooms) {
    if (room.peers.size === 0) rooms.delete(id);
  }
};

// ── Socket.IO signaling ───────────────────────────────────────────────────────
io.on('connection', socket => {
  const sessionUser = socket.request.session?.passport?.user
    ? findUserById(socket.request.session.passport.user) : null;

  let currentRoom      = null;
  let currentName      = null;
  let currentMeetingId = null;

  socket.on('join-room', ({ roomId, name }) => {
    if (!roomId || !name) return;
    if (currentRoom) leaveRoom();

    const targetRoom = roomId.toUpperCase();

    // ── Duplicate session check ───────────────────────────────────────────────
    // If this is a logged-in user, make sure they are not already inside this
    // room from another tab or window. Block the second connection immediately.
    if (sessionUser?.id && rooms.has(targetRoom)) {
      const existing = rooms.get(targetRoom);
      const alreadyIn = Array.from(existing.peers.values())
        .some(p => p.userId === sessionUser.id);

      if (alreadyIn) {
        socket.emit('join-error', {
          code:    'ALREADY_IN_ROOM',
          message: 'You are already in this meeting from another tab or window. Close that tab first.'
        });
        return; // stop here — do NOT add them to the room
      }
    }

    currentRoom = targetRoom;
    currentName = sessionUser ? sessionUser.name : name.trim().substring(0, 30);

    const isNew = !rooms.has(currentRoom);
    if (isNew) createRoom(currentRoom);

    const room = rooms.get(currentRoom);
    const existing = Array.from(room.peers.values()).map(p => ({ socketId: p.socketId, name: p.name }));

    room.peers.set(socket.id, { socketId: socket.id, name: currentName, userId: sessionUser?.id || null });
    socket.join(currentRoom);

    // Save to file
    const meetings = readMeetings();
    if (isNew) {
      const m = {
        id: uuidv4(), roomId: currentRoom,
        title:     `${currentName}'s Meeting`,
        hostId:    sessionUser?.id || null,
        hostName:  currentName,
        startedAt: new Date().toISOString(),
        endedAt: null, duration: null,
        participants: [{ userId: sessionUser?.id || null, name: currentName, joinedAt: new Date().toISOString(), leftAt: null }]
      };
      meetings.push(m);
      currentMeetingId = m.id;
    } else {
      const m = meetings.find(m => m.roomId === currentRoom && !m.endedAt);
      if (m) {
        m.participants.push({ userId: sessionUser?.id || null, name: currentName, joinedAt: new Date().toISOString(), leftAt: null });
        currentMeetingId = m.id;
      }
    }
    writeMeetings(meetings);

    socket.emit('room-joined', { roomId: currentRoom, peers: existing, mySocketId: socket.id });
    socket.to(currentRoom).emit('peer-joined', { socketId: socket.id, name: currentName });
  });

  socket.on('offer',         ({ to, offer })     => socket.to(to).emit('offer',         { from: socket.id, fromName: currentName, offer }));
  socket.on('answer',        ({ to, answer })    => socket.to(to).emit('answer',        { from: socket.id, answer }));
  socket.on('ice-candidate', ({ to, candidate }) => socket.to(to).emit('ice-candidate', { from: socket.id, candidate }));

  socket.on('chat-message', ({ roomId, text }) => {
    if (!currentRoom || currentRoom !== roomId?.toUpperCase()) return;
    socket.to(currentRoom).emit('chat-message', { from: socket.id, name: currentName, text: text.substring(0, 500), timestamp: Date.now() });
  });

  socket.on('media-state', ({ audio, video }) => {
    if (!currentRoom) return;
    socket.to(currentRoom).emit('peer-media-state', { socketId: socket.id, audio, video });
  });

  function leaveRoom() {
    if (!currentRoom) return;
    const room = rooms.get(currentRoom);
    if (room) {
      room.peers.delete(socket.id);
      socket.to(currentRoom).emit('peer-left', { socketId: socket.id, name: currentName });
    }
    socket.leave(currentRoom);

    if (currentMeetingId) {
      const meetings = readMeetings();
      const m = meetings.find(m => m.id === currentMeetingId);
      if (m) {
        const p = m.participants.filter(p => p.name === currentName).find(p => !p.leftAt);
        if (p) p.leftAt = new Date().toISOString();
        if (!room || room.peers.size === 0) {
          m.endedAt  = new Date().toISOString();
          m.duration = Math.floor((new Date(m.endedAt) - new Date(m.startedAt)) / 1000);
        }
        writeMeetings(meetings);
      }
    }

    cleanupEmptyRooms();
    currentRoom = null; currentMeetingId = null;
  }

  socket.on('leave-room',  leaveRoom);
  socket.on('disconnect', () => leaveRoom());
});

// ── Catch-all ─────────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});


// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => {
  console.log(`\n  NEXUS running → http://localhost:${PORT}`);
});

module.exports = { app, io };