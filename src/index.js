const express = require('express');
const cors = require('cors');
const app = express();

const allowedOrigins = [
  'https://convo-frontend-zxiovtysm-sugandhatiwari01s-projects.vercel.app',
  'http://localhost:3000' // For local testing
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// Routes (e.g., /api/auth/login, /api/users/search)
app.post('/api/auth/login', async (req, res) => { /* Login logic */ });
app.get('/api/users/search', authenticateJWT, async (req, res) => { /* Search logic */ });

// Add POST handler for /api/users/search to prevent 405 errors
app.post('/api/users/search', (req, res) => {
  res.status(405).json({ message: 'Method Not Allowed. Use GET /api/users/search instead.' });
});

app.listen(process.env.PORT || 5000, () => console.log('Server running'));