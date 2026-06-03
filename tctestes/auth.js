const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

const SECRET = "nutrivida_secret_key";

// BANCO
const db = new sqlite3.Database("./database.db");

db.run(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT
)
`);

// REGISTRO
app.post("/register", (req, res) => {
  const { username, password } = req.body;

  const hash = bcrypt.hashSync(password, 10);

  db.run(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    [username, hash],
    function (err) {
      if (err) return res.status(400).json({ error: "Usuário já existe" });

      res.json({ message: "Usuário criado!" });
    }
  );
});

// LOGIN
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (!user) return res.status(400).json({ error: "Usuário não encontrado" });

    const ok = bcrypt.compareSync(password, user.password);

    if (!ok) return res.status(400).json({ error: "Senha incorreta" });

    const token = jwt.sign({ id: user.id, username: user.username }, SECRET);

    res.json({ token, username: user.username });
  });
});

// VERIFICAR LOGIN
app.get("/me", (req, res) => {
  const token = req.headers.authorization;

  if (!token) return res.status(401).json({ error: "Sem token" });

  try {
    const decoded = jwt.verify(token, SECRET);
    res.json(decoded);
  } catch {
    res.status(401).json({ error: "Token inválido" });
  }
});

app.listen(3000, () => console.log("Servidor rodando na porta 3000"));