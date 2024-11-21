const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs-extra');
const path = require('path');
require('dotenv').config();

const REFRESH_TOKENS = path.join(__dirname, 'refreshTokens.json');

const generateAccessToken = (user) => {
  return jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
    expiresIn: process.env.ACCESS_JWT_EXPIRATION,
  });
};

const generateRefreshToken = () => {
  return crypto.randomBytes(40).toString('hex');
};

const getRefreshTokens = async () => {
  try {
    const data = await fs.readFile(REFRESH_TOKENS, 'utf-8');
    return JSON.parse(data);
  } catch {
    return [];
  }
};

const saveRefreshTokens = async (tokens) => {
  await fs.writeFile(REFRESH_TOKENS, JSON.stringify(tokens, null, 2));
};

const removeRefreshToken = (refreshToken, tokens) => {
  return tokens.filter((token) => token !== refreshToken);
};

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  getRefreshTokens,
  saveRefreshTokens,
  removeRefreshToken,
};
