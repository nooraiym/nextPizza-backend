const jwt = require('jsonwebtoken');
require('dotenv').config();
const { getUsers } = require('./utils');

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: 'Authorization header is required' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const users = await getUsers();
    const user = users.find((u) => u.id === decoded.id);

    if (!user) {
      return res.status(404).json({ error: 'User is not found' });
    }

    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

module.exports = { authenticateToken };
