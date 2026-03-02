import express from "express";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs/promises";

const app = express();
app.use(express.json());
app.use(cookieParser());

// ================= USERS =================
const USERS = {
  // ADMINS
  Piyush:  { password: "Piyush@987", fullName: "PIYUSH RAWAL", role: "admin" },
  Rushabh: { password: "Rvadnagra11@", fullName: "RUSHABH VADNAGRA", role: "admin" },
  Pankaj:  { password: "649", fullName: "PANKAJ SHAH", role: "admin" },

  // USERS
  FP13706: { password: "123", fullName: "DHIRUBHAI HADIYA", role: "user" },
  FP13707: { password: "123", fullName: "JITENDRABHAI JAIN", role: "user" },
  FP15081: { password: "123", fullName: "HARSH ZAVERI", role: "user" },
  FP16034: { password: "123", fullName: "BHAVESHKUMAR NAKUM", role: "user" },
  FP15812: { password: "123", fullName: "JATIN PRAJAPATI", role: "user" },
  FP14780: { password: "123", fullName: "SHILPABEN RATHOD", role: "user" },
  FP16205: { password: "123", fullName: "PRAKASH PATEL", role: "user" },
  FP16512: { password: "123", fullName: "MANN SHAH", role: "user" },
  FP14172: { password: "123", fullName: "RUSHABH VADNAGRA", role: "user" },
  FP14775: { password: "123", fullName: "DIPIKABEN PRAJAPATI", role: "user" },
  FP16376: { password: "123", fullName: "VIRAJBHAI SHAH", role: "user" },
  FP15711: { password: "123", fullName: "PRUTHVIRAJ GOHIL", role: "user" },
  FP16315: { password: "123", fullName: "SWATI PANDEY", role: "user" },
  FP13292: { password: "123", fullName: "MAHENDRA RAISING", role: "user" },
  FP14774: { password: "123", fullName: "ANIKET SAVAI", role: "user" },
  FP14761: { password: "123", fullName: "GAURAV RAWAL", role: "user" },
  FP14781: { password: "123", fullName: "AJAY MISIYE", role: "user" },
  FP13712: { password: "123", fullName: "ASHISH PANDYA", role: "user" },
  FP13468: { password: "123", fullName: "HEMAL SHAH", role: "user" },
  FP13973: { password: "123", fullName: "KANTI PRAJAPATI", role: "user" },
  FP14777: { password: "123", fullName: "JALPABEN PATEL", role: "user" },
  FP16379: { password: "123", fullName: "YOGESH GIRASE", role: "user" },
  FP16697: { password: "123", fullName: "PRATHAMESH DUSANE", role: "user" },
  FP16386: { password: "123", fullName: "DILIPBHAI PRAJAPATI", role: "user" },
  FP16809: { password: "123", fullName: "BHAVIKA KOSAMBIYA", role: "user" },
  FP16834: { password: "123", fullName: "SHRUTI LOKHANDE", role: "user" },
  SS1226:  { password: "123", fullName: "KARUNABEN AHIR", role: "user" },
  FP13289: { password: "123", fullName: "HIREN CHAUHAN", role: "user" },
  FP13681: { password: "123", fullName: "LALJIBHAI BALDANIYA", role: "user" },
  FP13692: { password: "123", fullName: "NILESHBHAI PATEL", role: "user" },
  FP14241: { password: "123", fullName: "KETAN PATEL", role: "user" },
  FP16393: { password: "123", fullName: "PRIYA BORADA", role: "user" },
  FP14173: { password: "123", fullName: "SACHIN PATEL", role: "user" },
  FP14689: { password: "123", fullName: "PRAHLAD PARMAR", role: "user" },
  FP15424: { password: "123", fullName: "RAKESH RAGHUVANSHI", role: "user" },
  FP14765: { password: "123", fullName: "SHARMILABEN PATEL", role: "user" }
};

// sessionId -> username
const sessions = new Map();

// ================= PERSISTENCE =================
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DATA_DIR = path.join(__dirname, "data");
const LEAVE_FILE = path.join(DATA_DIR, "leave-requests.json");

// username -> leaveRequests[]
let leaveStore = new Map();

function newId() {
  return crypto.randomBytes(12).toString("hex");
}

async function ensureDirs() {
  await fs.mkdir(DATA_DIR, { recursive: true });
}

async function loadLeaves() {
  try {
    const raw = await fs.readFile(LEAVE_FILE, "utf-8");
    const obj = JSON.parse(raw) || {};
    const m = new Map();
    for (const [u, arr] of Object.entries(obj)) {
      m.set(u, Array.isArray(arr) ? arr : []);
    }
    leaveStore = m;
  } catch {
    leaveStore = new Map();
  }
}

async function saveLeaves() {
  const obj = {};
  for (const [u, arr] of leaveStore.entries()) obj[u] = arr;
  await fs.writeFile(LEAVE_FILE, JSON.stringify(obj, null, 2), "utf-8");
}

// ================= AUTH HELPERS =================
function requireAuth(req, res, next) {
  const sid = req.cookies.sid;
  const username = sid && sessions.get(sid);
  if (!username) return res.status(401).send("Not logged in");
  req.username = username;
  next();
}

function requireAdmin(req, res, next) {
  const u = USERS[req.username];
  if (!u || u.role !== "admin") return res.status(403).send("Admin only");
  next();
}

function getMe(req) {
  return USERS[req.username] || { role: "user", fullName: req.username };
}

function getTargetUser(req) {
  const me = getMe(req);
  return (me.role === "admin" && req.query.user) ? req.query.user : req.username;
}

/* ✅ UPDATED: FULL / HALF / HOURS (with minutes) */
function validateLeavePayload(p) {
  const typeOk = ["CL", "SL", "PL", "HD"].includes(p.type);
  if (!typeOk) throw new Error("Invalid leave type");

  if (!p.fromDate || !/^\d{4}-\d{2}-\d{2}$/.test(p.fromDate)) throw new Error("fromDate required");
  if (!p.toDate || !/^\d{4}-\d{2}-\d{2}$/.test(p.toDate)) throw new Error("toDate required");

  const duration = String(p.duration || "").toUpperCase();
  if (!["FULL", "HALF", "HOURS"].includes(duration)) throw new Error("duration required");

  if (duration === "HALF" && !["FIRST", "SECOND"].includes(p.halfSession)) {
    throw new Error("halfSession required for half day");
  }

  if (duration === "HOURS") {
    const hc = Number(p.hoursCount || 0);
    const mc = Number(p.minutesCount || 0);

    if ((hc === 0 && mc === 0) || !Number.isFinite(hc) || !Number.isFinite(mc)) {
      throw new Error("hoursCount/minutesCount required for hours leave");
    }
    if (mc < 0 || mc > 59) throw new Error("minutesCount must be between 0 and 59");

    if (!["LATE", "EARLY"].includes(String(p.hoursType || "").toUpperCase())) {
      throw new Error("hoursType must be LATE or EARLY");
    }
  }

  if (!String(p.reason || "").trim()) throw new Error("reason required");
}

// ================= AUTH APIs =================
app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  const u = USERS[username];
  if (!u || u.password !== password) return res.status(401).send("Invalid credentials");

  const sid = newId();
  sessions.set(sid, username);

  res.cookie("sid", sid, { httpOnly: true, sameSite: "lax" });
  res.json({ ok: true });
});

app.post("/api/logout", (req, res) => {
  const sid = req.cookies.sid;
  if (sid) sessions.delete(sid);
  res.clearCookie("sid");
  res.json({ ok: true });
});

app.get("/api/me", requireAuth, (req, res) => {
  const u = USERS[req.username];
  res.json({
    username: req.username,
    fullName: u?.fullName || req.username,
    role: u?.role || "user"
  });
});

app.get("/api/users", requireAuth, requireAdmin, (req, res) => {
  const list = Object.entries(USERS).map(([username, u]) => ({
    username,
    fullName: u.fullName,
    role: u.role
  }));
  res.json(list);
});

// ================= LEAVE APIs =================

// User/Admin list leaves (admin can do ?user=)
app.get("/api/leaves", requireAuth, (req, res) => {
  const targetUser = getTargetUser(req);
  res.json(leaveStore.get(targetUser) || []);
});

// User creates request (only self)
app.post("/api/leaves", requireAuth, async (req, res) => {
  try {
    const payload = req.body || {};
    validateLeavePayload(payload);

    const duration = String(payload.duration || "FULL").toUpperCase();

    const items = leaveStore.get(req.username) || [];
    const leaveReq = {
      id: newId(),
      type: payload.type,
      fromDate: payload.fromDate,
      toDate: payload.toDate,
      duration,

      halfSession: duration === "HALF" ? (payload.halfSession || "") : "",

      hoursCount: duration === "HOURS" ? Number(payload.hoursCount || 0) : 0,
      minutesCount: duration === "HOURS" ? Number(payload.minutesCount || 0) : 0,
      hoursType: duration === "HOURS" ? String(payload.hoursType || "LATE").toUpperCase() : "",

      reason: String(payload.reason || "").trim(),

      status: "PENDING",
      adminRemark: "",
      decidedBy: "",
      decidedAt: "",

      createdAt: new Date().toISOString()
    };

    items.push(leaveReq);
    leaveStore.set(req.username, items);
    await saveLeaves();

    res.json(leaveReq);
  } catch (e) {
    res.status(400).send(String(e?.message || e));
  }
});

// User cancel only if PENDING
app.put("/api/leaves/:id/cancel", requireAuth, async (req, res) => {
  try {
    const items = leaveStore.get(req.username) || [];
    const idx = items.findIndex(x => x.id === req.params.id);
    if (idx === -1) return res.status(404).send("Not found");

    const st = String(items[idx].status || "").toUpperCase();
    if (st !== "PENDING") return res.status(400).send("Only pending can be cancelled");

    items[idx] = { ...items[idx], status: "CANCELLED" };
    leaveStore.set(req.username, items);
    await saveLeaves();

    res.json(items[idx]);
  } catch (e) {
    res.status(400).send(String(e?.message || e));
  }
});

// Admin approve/reject (needs ?user=)
app.put("/api/leaves/:id/decision", requireAuth, requireAdmin, async (req, res) => {
  try {
    const targetUser = req.query.user;
    if (!targetUser) return res.status(400).send("user query required");
    if (!USERS[targetUser]) return res.status(400).send("Unknown user");

    const { decision, adminRemark } = req.body || {};
    if (!["APPROVED", "REJECTED"].includes(String(decision || "").toUpperCase())) {
      return res.status(400).send("decision must be APPROVED or REJECTED");
    }

    const items = leaveStore.get(targetUser) || [];
    const idx = items.findIndex(x => x.id === req.params.id);
    if (idx === -1) return res.status(404).send("Not found");

    const st = String(items[idx].status || "").toUpperCase();
    if (st !== "PENDING") return res.status(400).send("Only pending can be approved/rejected");

    items[idx] = {
      ...items[idx],
      status: String(decision).toUpperCase(),
      adminRemark: String(adminRemark || "").trim(),
      decidedBy: req.username,
      decidedAt: new Date().toISOString()
    };

    leaveStore.set(targetUser, items);
    await saveLeaves();

    res.json(items[idx]);
  } catch (e) {
    res.status(400).send(String(e?.message || e));
  }
});

// Admin dashboard (all users combined)
app.get("/api/admin/leaves/dashboard", requireAuth, requireAdmin, (req, res) => {
  const users = Object.entries(USERS)
    .filter(([, u]) => u.role === "user")
    .map(([username, u]) => {
      const leaves = leaveStore.get(username) || [];
      return { username, fullName: u.fullName, leaves };
    });

  res.json({ users });
});

// ================= STATIC =================
app.use(express.static(path.join(__dirname, "public")));
app.get("/", (req, res) => res.redirect("/login.html"));

// ================= START =================
(async function boot() {
  await ensureDirs();
  await loadLeaves();
  await saveLeaves();

  app.listen(3003, () => {
    console.log("✅ Running: http://localhost:3003/login.html");
  });
})();
