const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();
const users = [];

app.use(
  cors({
    origin: process.env.CORS_ORIGIN,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true,
  })
);
app.use(bodyParser.json());

app.get('/api/hello', (req, res) => {
  res.json({ message: 'Hello from backend!' });
});

const generateToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
};

const authenticateToken = (req, res, next) => {
  const token = req.headers['authToken'];
  if (!token) {
    return res.status(401).json({ message: 'Токен отсутствует' });
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Недействительный токен' });
    }
    req.user = user;
    next();
  });
};

app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ message: 'Все поля обязательны' });
  }

  const existingUser = users.find((user) => user.email === email);
  if (existingUser) {
    return res.status(409).json({ message: 'Пользователь уже существует' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = { id: uuidv4(), name, email, password: hashedPassword };
  users.push(user);

  const token = generateToken(user.id);
  res.status(201).json({ message: 'Регистрация успешна', token });
});

app.post('/api/auth', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Все поля обязательны' });
  }

  const user = users.find((user) => user.email === email);
  if (!user) {
    return res.status(401).json({ message: 'Неверные учетные данные' });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).json({ message: 'Неверные учетные данные' });
  }

  const token = generateToken(user.id);
  res.status(200).json({ token });
});

app.get('/profile', authenticateToken, (req, res) => {
  const user = users.find((user) => user.id === req.user.userId);

  if (!user) {
    return res.status(404).json({ message: 'Пользователь не найден' });
  }

  const { password, ...profile } = user;
  res.status(200).json(profile);
});


module.exports = app;
