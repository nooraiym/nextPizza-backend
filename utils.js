const fs = require('fs-extra');
const path = require('path');
const bcrypt = require('bcryptjs');

const MOCK_USERS = path.join(__dirname, 'users.json');

const getUsers = async () => {
  try {
    const data = await fs.readFile(MOCK_USERS, 'utf-8');
    return JSON.parse(data);
  } catch {
    return [];
  }
};

const saveUsers = async (users) => {
  await fs.writeFile(MOCK_USERS, JSON.stringify(users, null, 2));
};

const hashPassword = async (password) => {
  return await bcrypt.hash(password, 10);
};

const comparePassword = async (password, hash) => {
  return await bcrypt.compare(password, hash);
};

module.exports = {
  getUsers,
  saveUsers,
  hashPassword,
  comparePassword,
};
