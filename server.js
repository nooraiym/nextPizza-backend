const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();
const {
  getUsers,
  hashPassword,
  saveUsers,
  comparePassword,
} = require('./utils');
const { authenticateToken } = require('./middleware');
const {
  generateAccessToken,
  generateRefreshToken,
  getRefreshTokens,
  saveRefreshTokens,
  removeRefreshToken,
} = require('./tokenUtils');

const app = express();

app.use(
  cors({
    origin: [process.env.CORS_ORIGIN, process.env.CORS_LOCAL],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  })
);
app.options('*', cors());
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use((err, req, res, next) => {
  if (err.name === 'Error' && err.message === 'Not allowed by CORS') {
    res.status(403).json({ message: 'CORS error: Origin not allowed' });
  } else {
    next(err);
  }
});

app.get('/api/hello', (req, res) => {
  res.json({ message: 'Hello from backend!' });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'All fields required' });
  }

  const users = await getUsers();
  const user = users.find((user) => user.email === email);
  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const isPasswordValid = await comparePassword(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken();
  const tokens = await getRefreshTokens();
  tokens.push(refreshToken);
  await saveRefreshTokens(tokens);

  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
  });

  res.status(200).json({ message: 'Login successful', accessToken });
});

app.post('/api/token', async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token is required' });
  }

  const tokens = await getRefreshTokens();

  if (!tokens.includes(refreshToken)) {
    return res.status(403).json({ error: 'Invalid refresh token' });
  }

  const users = await getUsers();
  const user = users.find((u) => u.id);

  if (!user) {
    return res.status(403).json({ error: 'User not found' });
  }

  const newAccessToken = generateAccessToken(user);
  const newRefreshToken = generateRefreshToken();

  const updatedTokens = removeRefreshToken(refreshToken, tokens);
  updatedTokens.push(newRefreshToken);
  await saveRefreshTokens(updatedTokens);

  res.cookie('refreshToken', newRefreshToken, {
    httpOnly: true,
    secure: false,
    sameSite: 'strict',
  });

  res.status(200).json({ accessToken: newAccessToken });
});

app.post('/api/logout', async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token is required' });
  }

  const tokens = await getRefreshTokens();
  const updatedTokens = removeRefreshToken(refreshToken, tokens);
  await saveRefreshTokens(updatedTokens);

  res.clearCookie('refreshToken');
  res.status(200).json({ message: 'Logged out successfully' });
});

app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: 'All fields required' });
  }

  const users = await getUsers();
  const existingUser = users.find((user) => user.email === email);
  if (existingUser) {
    return res.status(409).json({ message: 'User is already exist' });
  }

  const hashedPassword = await hashPassword(password);
  const newUser = { id: uuidv4(), username, email, password: hashedPassword };
  users.push(newUser);
  await saveUsers(users);

  const accessToken = generateAccessToken(newUser);
  const refreshToken = generateRefreshToken();

  const tokens = await getRefreshTokens();
  tokens.push(refreshToken);
  await saveRefreshTokens(tokens);

  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: false,
    sameSite: 'strict',
  });

  res.status(201).json(accessToken);
});

app.get('/api/profile', authenticateToken, async (req, res) => {
  const { user } = req;
  res.status(200).json({
    id: user.id,
    username: user.username,
    email: user.email,
  });
});

module.exports = app;
