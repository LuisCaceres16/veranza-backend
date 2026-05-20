const express    = require('express');
const { Pool }   = require('pg');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors({
  origin: function (origin, callback) {
    const allowed = [
      process.env.FRONTEND_URL,
      'http://localhost:3000',
      'http://localhost:3001',
      'http://localhost:3002',
    ].filter(Boolean);
    if (!origin || allowed.includes(origin)) return callback(null, true);
    callback(new Error('No permitido por CORS'));
  },
  credentials: true,
}));

// ── Conexión PostgreSQL ───────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

const JWT_SECRET = process.env.JWT_SECRET || 'veranza_secret_2024';

// ── Middleware auth ───────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token requerido' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido' });
  }
}

// ── Inicializar tablas ────────────────────────────────────────────
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS usuarios (
        id          SERIAL PRIMARY KEY,
        nombre      VARCHAR(100) NOT NULL,
        email       VARCHAR(100) UNIQUE NOT NULL,
        password    VARCHAR(255) NOT NULL,
        rol         VARCHAR(20) DEFAULT 'agente',
        telefono    VARCHAR(20) DEFAULT NULL,
        creado_en   TIMESTAMP DEFAULT NOW()
      )
    `);
    // Agregar columna telefono si no existe
    try {
      await client.query("ALTER TABLE usuarios ADD COLUMN telefono VARCHAR(20) DEFAULT NULL");
    } catch(e) { /* ya existe */ }

    // Tabla de semanas bloqueadas
    await client.query(`
      CREATE TABLE IF NOT EXISTS semanas_bloqueadas (
        id           SERIAL PRIMARY KEY,
        fecha_inicio DATE NOT NULL,
        fecha_fin    DATE NOT NULL,
        motivo       VARCHAR(200),
        activo       BOOLEAN DEFAULT TRUE,
        creado_en    TIMESTAMP DEFAULT NOW()
      )
    `);

    // Tabla de encargados independiente
    await client.query(`
      CREATE TABLE IF NOT EXISTS encargados (
        id         SERIAL PRIMARY KEY,
        nombre     VARCHAR(100) NOT NULL,
        telefono   VARCHAR(20) NOT NULL,
        activo     BOOLEAN DEFAULT TRUE,
        creado_en  TIMESTAMP DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS clientes (
        id              SERIAL PRIMARY KEY,
        nombre_apellido VARCHAR(150) NOT NULL,
        telefono        VARCHAR(30),
        correo          VARCHAR(100),
        mejor_contacto  VARCHAR(50),
        red_social      VARCHAR(100),
        fecha           DATE,
        fecha_cita      TIMESTAMP WITHOUT TIME ZONE,
        encargado       VARCHAR(100),
        opciones_cita   TEXT,
        observaciones   TEXT,
        registrado_por  INTEGER REFERENCES usuarios(id),
        creado_en       TIMESTAMP DEFAULT NOW(),
        actualizado_en  TIMESTAMP DEFAULT NOW()
      )
    `);

    // Admin por defecto
    const { rows } = await client.query('SELECT id FROM usuarios WHERE email = $1', ['admin@veranza.com']);
    if (rows.length === 0) {
      const hash = await bcrypt.hash('veranza2024', 10);
      await client.query(
        'INSERT INTO usuarios (nombre, email, password, rol) VALUES ($1,$2,$3,$4)',
        ['Administrador', 'admin@veranza.com', hash, 'admin']
      );
      console.log('✅ Usuario admin creado: admin@veranza.com / veranza2024');
    }
    console.log('✅ Base de datos inicializada');
  } finally {
    client.release();
  }
}

// ── AUTH ──────────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Campos requeridos' });
  try {
    const { rows } = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    if (!rows.length) return res.status(401).json({ error: 'Credenciales incorrectas' });
    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Credenciales incorrectas' });
    const token = jwt.sign(
      { id: user.id, nombre: user.nombre, email: user.email, rol: user.rol },
      JWT_SECRET, { expiresIn: '8h' }
    );
    res.json({ token, user: { id: user.id, nombre: user.nombre, email: user.email, rol: user.rol } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── CLIENTES ──────────────────────────────────────────────────────
app.get('/api/clientes', authMiddleware, async (req, res) => {
  try {
    const { buscar, pagina = 1, limite = 20 } = req.query;
    const offset = (pagina - 1) * limite;
    let where = '';
    let params = [];

    if (buscar) {
      where = `WHERE (c.nombre_apellido ILIKE $1 OR c.telefono ILIKE $1 OR c.correo ILIKE $1 OR c.encargado ILIKE $1)`;
      params = [`%${buscar}%`];
    }

    const dataQuery = `
      SELECT c.*, u.nombre AS agente
      FROM clientes c
      LEFT JOIN usuarios u ON c.registrado_por = u.id
      ${where}
      ORDER BY c.creado_en DESC
      LIMIT ${Number(limite)} OFFSET ${Number(offset)}
    `;
    const countQuery = `SELECT COUNT(*) as total FROM clientes c ${where}`;

    const [dataRes, countRes] = await Promise.all([
      pool.query(dataQuery, params),
      pool.query(countQuery, params),
    ]);

    res.json({
      clientes: dataRes.rows,
      total: parseInt(countRes.rows[0].total),
      pagina: Number(pagina),
      limite: Number(limite),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/clientes/:id', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT c.*, u.nombre AS agente FROM clientes c LEFT JOIN usuarios u ON c.registrado_por = u.id WHERE c.id = $1',
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'No encontrado' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/clientes', authMiddleware, async (req, res) => {
  const { nombre_apellido, telefono, correo, mejor_contacto, red_social, fecha, fecha_cita, encargado, opciones_cita, observaciones } = req.body;
  if (!nombre_apellido) return res.status(400).json({ error: 'Nombre requerido' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO clientes
        (nombre_apellido, telefono, correo, mejor_contacto, red_social, fecha, fecha_cita, encargado, opciones_cita, observaciones, registrado_por)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id`,
      [nombre_apellido, telefono||null, correo||null, mejor_contacto||null, red_social||null,
       fecha||null, fecha_cita||null, encargado||null, opciones_cita||null, observaciones||null, req.user.id]
    );
    res.status(201).json({ id: rows[0].id, mensaje: 'Cliente registrado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/clientes/:id', authMiddleware, async (req, res) => {
  const { nombre_apellido, telefono, correo, mejor_contacto, red_social, fecha, fecha_cita, encargado, opciones_cita, observaciones } = req.body;
  try {
    await pool.query(
      `UPDATE clientes SET
        nombre_apellido=$1, telefono=$2, correo=$3, mejor_contacto=$4, red_social=$5,
        fecha=$6, fecha_cita=$7, encargado=$8, opciones_cita=$9, observaciones=$10,
        actualizado_en=NOW()
       WHERE id=$11`,
      [nombre_apellido, telefono||null, correo||null, mejor_contacto||null, red_social||null,
       fecha||null, fecha_cita||null, encargado||null, opciones_cita||null, observaciones||null, req.params.id]
    );
    res.json({ mensaje: 'Actualizado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/clientes/:id', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM clientes WHERE id = $1', [req.params.id]);
    res.json({ mensaje: 'Eliminado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── REGISTRO PÚBLICO (sin auth) ───────────────────────────────────
app.post('/api/registro-publico', async (req, res) => {
  const { nombre_apellido, telefono, correo, mejor_contacto, red_social, opciones_cita, fecha } = req.body;
  if (!nombre_apellido || !telefono) {
    return res.status(400).json({ error: 'Nombre y teléfono son requeridos' });
  }
  try {
    await pool.query(
      `INSERT INTO clientes (nombre_apellido, telefono, correo, mejor_contacto, red_social, opciones_cita, fecha)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [nombre_apellido, telefono, correo||null, mejor_contacto||null, red_social||null, opciones_cita||null, fecha||null]
    );
    res.status(201).json({ mensaje: 'Solicitud recibida' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── USUARIOS ──────────────────────────────────────────────────────
app.get('/api/usuarios', authMiddleware, async (req, res) => {
  if (req.user.rol !== 'admin') return res.status(403).json({ error: 'Sin permiso' });
  const { rows } = await pool.query('SELECT id, nombre, email, rol, telefono, creado_en FROM usuarios ORDER BY creado_en DESC');
  res.json(rows);
});

app.post('/api/usuarios', authMiddleware, async (req, res) => {
  if (req.user.rol !== 'admin') return res.status(403).json({ error: 'Sin permiso' });
  const { nombre, email, password, rol } = req.body;
  if (!nombre || !email || !password) return res.status(400).json({ error: 'Campos requeridos' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const { telefono: tel } = req.body;
    await pool.query(
      'INSERT INTO usuarios (nombre, email, password, rol, telefono) VALUES ($1,$2,$3,$4,$5)',
      [nombre, email, hash, rol || 'agente', tel || null]
    );
    res.status(201).json({ mensaje: 'Usuario creado' });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Email ya registrado' });
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/usuarios/:id', authMiddleware, async (req, res) => {
  if (req.user.rol !== 'admin') return res.status(403).json({ error: 'Sin permiso' });
  const { nombre, telefono } = req.body;
  try {
    await pool.query('UPDATE usuarios SET nombre=$1, telefono=$2 WHERE id=$3', [nombre, telefono||null, req.params.id]);
    res.json({ mensaje: 'Usuario actualizado' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/usuarios/:id', authMiddleware, async (req, res) => {
  if (req.user.rol !== 'admin') return res.status(403).json({ error: 'Sin permiso' });
  try {
    await pool.query("DELETE FROM usuarios WHERE id = $1 AND rol != 'admin'", [req.params.id]);
    res.json({ mensaje: 'Usuario eliminado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── SEMANAS BLOQUEADAS ───────────────────────────────────────────
app.get('/api/semanas-bloqueadas', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM semanas_bloqueadas WHERE activo=true ORDER BY fecha_inicio ASC');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/semanas-bloqueadas', authMiddleware, async (req, res) => {
  if (req.user.rol !== 'admin') return res.status(403).json({ error: 'Sin permiso' });
  const { fecha_inicio, fecha_fin, motivo } = req.body;
  if (!fecha_inicio || !fecha_fin) return res.status(400).json({ error: 'Fechas requeridas' });
  try {
    const { rows } = await pool.query(
      'INSERT INTO semanas_bloqueadas (fecha_inicio, fecha_fin, motivo) VALUES ($1,$2,$3) RETURNING *',
      [fecha_inicio, fecha_fin, motivo || null]
    );
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/semanas-bloqueadas/:id', authMiddleware, async (req, res) => {
  if (req.user.rol !== 'admin') return res.status(403).json({ error: 'Sin permiso' });
  try {
    await pool.query('UPDATE semanas_bloqueadas SET activo=false WHERE id=$1', [req.params.id]);
    res.json({ mensaje: 'Eliminado' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── ENCARGADOS ───────────────────────────────────────────────────
app.get('/api/encargados', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM encargados WHERE activo=true ORDER BY nombre ASC');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/encargados', authMiddleware, async (req, res) => {
  if (req.user.rol !== 'admin') return res.status(403).json({ error: 'Sin permiso' });
  const { nombre, telefono } = req.body;
  if (!nombre || !telefono) return res.status(400).json({ error: 'Nombre y teléfono requeridos' });
  try {
    const { rows } = await pool.query(
      'INSERT INTO encargados (nombre, telefono) VALUES ($1,$2) RETURNING *',
      [nombre, telefono]
    );
    res.status(201).json(rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/encargados/:id', authMiddleware, async (req, res) => {
  if (req.user.rol !== 'admin') return res.status(403).json({ error: 'Sin permiso' });
  const { nombre, telefono } = req.body;
  try {
    await pool.query('UPDATE encargados SET nombre=$1, telefono=$2 WHERE id=$3', [nombre, telefono, req.params.id]);
    res.json({ mensaje: 'Actualizado' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/encargados/:id', authMiddleware, async (req, res) => {
  if (req.user.rol !== 'admin') return res.status(403).json({ error: 'Sin permiso' });
  try {
    await pool.query('UPDATE encargados SET activo=false WHERE id=$1', [req.params.id]);
    res.json({ mensaje: 'Eliminado' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/health', (req, res) => res.json({ status: 'ok', proyecto: 'Veranza Residencial' }));

// ── Iniciar ───────────────────────────────────────────────────────
const PORT = process.env.PORT || 4000;
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🏠 Veranza API corriendo en puerto ${PORT}`);

    // Keep-alive para Render
    if (process.env.RENDER_URL) {
      const https = require('https');
      setInterval(() => {
        https.get(process.env.RENDER_URL + '/api/health', (res) => {
          console.log('💓 Keep-alive: ' + res.statusCode);
        }).on('error', () => {});
      }, 10 * 60 * 1000);
      console.log('💓 Keep-alive activado');
    }
  });
}).catch(console.error);
