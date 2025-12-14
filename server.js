import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import pkg from "pg";
const { Pool } = pkg;

const app = express();
app.use(cors());
app.use(express.json());

// Root check
app.get("/", (req, res) => res.send("API up"));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";

// Ensure tables exist on startup (so signup doesn't fail if tables are missing)
async function ensureSchema() {
  await pool.query(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
      username text UNIQUE NOT NULL,
      password text NOT NULL,
      avatar text DEFAULT ''
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
      room text NOT NULL,
      user_id uuid REFERENCES users(id),
      text text NOT NULL,
      created_at timestamptz DEFAULT now()
    );
  `);
  console.log("DB schema ready");
}

const sign = (u) => jwt.sign({ id: u.id, username: u.username }, JWT_SECRET, { expiresIn: "7d" });
const auth = (req, res, next) => {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: "unauthorized" }); }
};

// Auth
app.post("/api/signup", async (req, res) => {
  const { username, password, avatar = "" } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "username and password required" });
  const hashed = await bcrypt.hash(password, 10);
  try {
    const { rows } = await pool.query(
      "INSERT INTO users (username,password,avatar) VALUES ($1,$2,$3) RETURNING id,username,avatar",
      [username, hashed, avatar]
    );
    const user = rows[0];
    res.json({ token: sign(user), user });
  } catch (e) {
    if (e.code === "23505") return res.status(400).json({ error: "username exists" });
    console.error("Signup failed:", e);
    res.status(500).json({ error: e.detail || e.message || "signup failed" });
  }
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body || {};
  const { rows } = await pool.query("SELECT * FROM users WHERE username=$1", [username]);
  const user = rows[0];
  if (!user) return res.status(400).json({ error: "invalid credentials" });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(400).json({ error: "invalid credentials" });
  res.json({ token: sign(user), user: { id: user.id, username: user.username, avatar: user.avatar || "" } });
});

app.get("/api/me", auth, async (req, res) => {
  const { rows } = await pool.query("SELECT id,username,avatar FROM users WHERE id=$1", [req.user.id]);
  res.json(rows[0]);
});

app.put("/api/me", auth, async (req, res) => {
  const { avatar = "" } = req.body || {};
  const { rows } = await pool.query(
    "UPDATE users SET avatar=$1 WHERE id=$2 RETURNING id,username,avatar",
    [avatar, req.user.id]
  );
  res.json(rows[0]);
});

// Messages
app.post("/api/messages", auth, async (req, res) => {
  const { room = "global", text } = req.body || {};
  if (!text) return res.status(400).json({ error: "text required" });
  const { rows } = await pool.query(
    "INSERT INTO messages (room,user_id,text) VALUES ($1,$2,$3) RETURNING id,room,user_id,text,created_at",
    [room, req.user.id, text]
  );
  res.json(rows[0]);
});

app.get("/api/messages", auth, async (req, res) => {
  const room = req.query.room || "global";
  const { rows } = await pool.query(
    `SELECT m.id,m.room,m.text,m.created_at,u.username,u.avatar
     FROM messages m JOIN users u ON u.id=m.user_id
     WHERE room=$1
     ORDER BY created_at DESC
     LIMIT 50`,
    [room]
  );
  res.json(rows.reverse());
});

const port = process.env.PORT || 3000;
ensureSchema()
  .then(() => {
    app.listen(port, () => console.log("API listening on", port));
  })
  .catch((err) => {
    console.error("Failed to init DB schema", err);
    process.exit(1);
  });
