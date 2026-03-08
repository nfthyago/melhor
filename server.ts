import express from 'express';
import { createServer as createViteServer } from 'vite';
import Database from 'better-sqlite3';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const db = new Database('database.db');
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Initialize Database
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE,
    password TEXT,
    name TEXT
  );

  CREATE TABLE IF NOT EXISTS indicacoes (
    id TEXT PRIMARY KEY,
    nome TEXT,
    valor_indicacao REAL,
    usuario_id TEXT,
    FOREIGN KEY(usuario_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS clientes (
    id TEXT PRIMARY KEY,
    nome TEXT,
    whatsapp TEXT,
    indicacao_id TEXT,
    afiliado TEXT,
    status TEXT,
    data_cadastro TEXT,
    usuario_id TEXT,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(usuario_id) REFERENCES users(id),
    FOREIGN KEY(indicacao_id) REFERENCES indicacoes(id)
  );

  CREATE TABLE IF NOT EXISTS contas_pagar (
    id TEXT PRIMARY KEY,
    descricao TEXT,
    valor REAL,
    status TEXT,
    data_vencimento TEXT,
    dividir_entre_usuarios INTEGER,
    usuarios_participantes TEXT, -- JSON array
    usuario_id TEXT,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(usuario_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS contas_receber (
    id TEXT PRIMARY KEY,
    descricao TEXT,
    valor REAL,
    status TEXT,
    data_vencimento TEXT,
    cliente_id TEXT,
    usuario_id TEXT,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(usuario_id) REFERENCES users(id),
    FOREIGN KEY(cliente_id) REFERENCES clientes(id)
  );
`);

async function startServer() {
  const app = express();
  app.use(express.json());
  app.use(cors());

  // Auth Middleware
  const authenticateToken = (req: any, res: any, next: any) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    });
  };

  // Auth Routes
  app.post('/api/auth/register', async (req, res) => {
    const { email, password, name } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const id = Math.random().toString(36).substr(2, 9);

    try {
      db.prepare('INSERT INTO users (id, email, password, name) VALUES (?, ?, ?, ?)').run(id, email, hashedPassword, name);
      const token = jwt.sign({ id, email, name }, JWT_SECRET);
      res.json({ token, user: { id, email, name } });
    } catch (e) {
      res.status(400).json({ error: 'Email already exists' });
    }
  });

  app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email) as any;

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET);
    res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
  });

  // Users Route (for sharing bills)
  app.get('/api/users', authenticateToken, (req, res) => {
    const users = db.prepare('SELECT id, email, name FROM users').all();
    res.json(users);
  });

  // Clientes Routes
  app.get('/api/clientes', authenticateToken, (req: any, res) => {
    const clientes = db.prepare('SELECT * FROM clientes WHERE usuario_id = ?').all(req.user.id);
    res.json(clientes);
  });

  app.post('/api/clientes', authenticateToken, (req: any, res) => {
    const { nome, whatsapp, indicacao_id, afiliado, status, data_cadastro } = req.body;
    const id = Math.random().toString(36).substr(2, 9);
    db.prepare('INSERT INTO clientes (id, nome, whatsapp, indicacao_id, afiliado, status, data_cadastro, usuario_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(id, nome, whatsapp, indicacao_id, afiliado, status, data_cadastro, req.user.id);
    res.json({ id });
  });

  app.put('/api/clientes/:id', authenticateToken, (req: any, res) => {
    const { nome, whatsapp, indicacao_id, afiliado, status, data_cadastro } = req.body;
    db.prepare('UPDATE clientes SET nome = ?, whatsapp = ?, indicacao_id = ?, afiliado = ?, status = ?, data_cadastro = ? WHERE id = ? AND usuario_id = ?')
      .run(nome, whatsapp, indicacao_id, afiliado, status, data_cadastro, req.params.id, req.user.id);
    res.json({ success: true });
  });

  app.delete('/api/clientes/:id', authenticateToken, (req: any, res) => {
    db.prepare('DELETE FROM clientes WHERE id = ? AND usuario_id = ?').run(req.params.id, req.user.id);
    res.json({ success: true });
  });

  // Indicações Routes
  app.get('/api/indicacoes', authenticateToken, (req: any, res) => {
    const indicacoes = db.prepare('SELECT * FROM indicacoes WHERE usuario_id = ?').all(req.user.id);
    res.json(indicacoes);
  });

  app.post('/api/indicacoes', authenticateToken, (req: any, res) => {
    const { nome, valor_indicacao } = req.body;
    const id = Math.random().toString(36).substr(2, 9);
    db.prepare('INSERT INTO indicacoes (id, nome, valor_indicacao, usuario_id) VALUES (?, ?, ?, ?)').run(id, nome, valor_indicacao, req.user.id);
    res.json({ id });
  });

  app.put('/api/indicacoes/:id', authenticateToken, (req: any, res) => {
    const { nome, valor_indicacao } = req.body;
    db.prepare('UPDATE indicacoes SET nome = ?, valor_indicacao = ? WHERE id = ? AND usuario_id = ?').run(nome, valor_indicacao, req.params.id, req.user.id);
    res.json({ success: true });
  });

  app.delete('/api/indicacoes/:id', authenticateToken, (req: any, res) => {
    db.prepare('DELETE FROM indicacoes WHERE id = ? AND usuario_id = ?').run(req.params.id, req.user.id);
    res.json({ success: true });
  });

  // Contas a Pagar Routes
  app.get('/api/contas-pagar', authenticateToken, (req: any, res) => {
    // Show bills created by user OR where user is participant
    const bills = db.prepare(`
      SELECT * FROM contas_pagar 
      WHERE usuario_id = ? 
      OR usuarios_participantes LIKE ?
    `).all(req.user.id, `%${req.user.id}%`);
    
    res.json(bills.map((b: any) => ({
      ...b,
      usuarios_participantes: JSON.parse(b.usuarios_participantes || '[]'),
      dividir_entre_usuarios: !!b.dividir_entre_usuarios
    })));
  });

  app.post('/api/contas-pagar', authenticateToken, (req: any, res) => {
    const { descricao, valor, status, data_vencimento, dividir_entre_usuarios, usuarios_participantes } = req.body;
    const id = Math.random().toString(36).substr(2, 9);
    db.prepare('INSERT INTO contas_pagar (id, descricao, valor, status, data_vencimento, dividir_entre_usuarios, usuarios_participantes, usuario_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(id, descricao, valor, status, data_vencimento, dividir_entre_usuarios ? 1 : 0, JSON.stringify(usuarios_participantes || []), req.user.id);
    res.json({ id });
  });

  app.put('/api/contas-pagar/:id', authenticateToken, (req: any, res) => {
    const { descricao, valor, status, data_vencimento, dividir_entre_usuarios, usuarios_participantes } = req.body;
    db.prepare('UPDATE contas_pagar SET descricao = ?, valor = ?, status = ?, data_vencimento = ?, dividir_entre_usuarios = ?, usuarios_participantes = ? WHERE id = ? AND usuario_id = ?')
      .run(descricao, valor, status, data_vencimento, dividir_entre_usuarios ? 1 : 0, JSON.stringify(usuarios_participantes || []), req.params.id, req.user.id);
    res.json({ success: true });
  });

  app.delete('/api/contas-pagar/:id', authenticateToken, (req: any, res) => {
    db.prepare('DELETE FROM contas_pagar WHERE id = ? AND usuario_id = ?').run(req.params.id, req.user.id);
    res.json({ success: true });
  });

  // Contas a Receber Routes
  app.get('/api/contas-receber', authenticateToken, (req: any, res) => {
    const bills = db.prepare('SELECT * FROM contas_receber WHERE usuario_id = ?').all(req.user.id);
    res.json(bills);
  });

  app.post('/api/contas-receber', authenticateToken, (req: any, res) => {
    const { descricao, valor, status, data_vencimento, cliente_id } = req.body;
    const id = Math.random().toString(36).substr(2, 9);
    db.prepare('INSERT INTO contas_receber (id, descricao, valor, status, data_vencimento, cliente_id, usuario_id) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(id, descricao, valor, status, data_vencimento, cliente_id, req.user.id);
    res.json({ id });
  });

  app.put('/api/contas-receber/:id', authenticateToken, (req: any, res) => {
    const { descricao, valor, status, data_vencimento, cliente_id } = req.body;
    db.prepare('UPDATE contas_receber SET descricao = ?, valor = ?, status = ?, data_vencimento = ?, cliente_id = ? WHERE id = ? AND usuario_id = ?')
      .run(descricao, valor, status, data_vencimento, cliente_id, req.params.id, req.user.id);
    res.json({ success: true });
  });

  app.delete('/api/contas-receber/:id', authenticateToken, (req: any, res) => {
    db.prepare('DELETE FROM contas_receber WHERE id = ? AND usuario_id = ?').run(req.params.id, req.user.id);
    res.json({ success: true });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (req, res) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  }

  const PORT = 3000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
