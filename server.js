const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const User = require('./models/users');
const app = express();

app.use(express.json());
app.use(cors());

const secretKey = 'cAtwa1kkEy';

const mongoURI =
  'mongodb+srv://Dmitry:admin@cluster0.ypdufpr.mongodb.net/node-reg-auth?retryWrites=true&w=majority';
mongoose
  .connect(mongoURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log('Подключено к MongoDB');
  })
  .catch((error) => {
    console.error('Ошибка подключения к MongoDB:', error);
  });

const generateToken = (user) => {
  const payload = {
    id: user.id,
    name: user.name,
  };
  const options = { expiresIn: '1h' };

  return jwt.sign(payload, secretKey, options);
};

const authenticateUser = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Отсутствует токен авторизации' });
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'Истек срок действия токена авторизации' });
      }
      return res.status(403).json({ error: 'Неверный токен авторизации' });
    }

    req.user = decoded;
    next();
  });

};

app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res
        .status(400)
        .json({ error: 'Пользователь с такой электронной почтой уже существует' });
    }

    const newUser = new User({
      name,
      email,
      password,
      registrationDate: new Date(),
      lastLoginDate: null,
      status: 'normal',
    });

    await newUser.save();
    res.status(201).json({ message: 'Пользователь успешно зарегистрирован' });
  } catch (error) {
    console.error('Ошибка при регистрации пользователя:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Неверные учетные данные' });
    }

    if (user.status === 'blocked') {
      return res
        .status(403)
        .json({ error: 'Невозможно зайти в учетную запись. Вы заблокированы!' });
    }

    const passwordMatch = password === user.password;
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Неверные учетные данные' });
    }

    user.lastLoginDate = new Date();
    user.status = 'active';
    await user.save();
    const token = generateToken(user);
    res.json({ token });
  } catch (error) {
    console.error('Ошибка при аутентификации пользователя:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.get('/api/users', authenticateUser, async (req, res) => {
  try {
    const users = await User.find();
    res.json(users);
  } catch (error) {
    console.error('Ошибка при получении пользователей:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.get('/api/users/:email', authenticateUser, async (req, res) => {
  try {
    const { email } = req.params;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }

    res.json(user);
  } catch (error) {
    console.error('Ошибка при поиске пользователя:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.get('/api/users/currentUser/:email', authenticateUser, async (req, res) => {
  try {
    const { email } = req.params;
    const currentUser = await User.findOne({ email });
    if (!currentUser) {
      return res.status(404).json({ error: 'Текущий пользователь не найден' });
    }

    res.json(currentUser);
  } catch (error) {
    console.error('Ошибка при получении текущего пользователя:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.put('/api/users/currentUser/:email/status', authenticateUser, async (req, res) => {
  try {
    const { email } = req.params;
    const { status } = req.body;
    const currentUser = await User.findOneAndUpdate({ email }, { status }, { new: true });
    if (!currentUser) {
      return res.status(404).json({ error: 'Текущий пользователь не найден' });
    }

    res.json({ message: 'Статус текущего пользователя успешно обновлен', currentUser });
  } catch (error) {
    console.error('Ошибка при обновлении статуса текущего пользователя:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.put('/api/users/block', authenticateUser, async (req, res) => {
  try {
    const { userIds } = req.body;
    await User.updateMany({ _id: { $in: userIds } }, { status: 'blocked' });
    res.json({ message: 'Пользователи заблокированы' });
  } catch (error) {
    console.error('Ошибка при блокировке пользователей:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.put('/api/users/unblock', authenticateUser, async (req, res) => {
  try {
    const { userIds } = req.body;
    await User.updateMany({ _id: { $in: userIds } }, { status: 'normal' });
    res.json({ message: 'Пользователи разблокированы' });
  } catch (error) {
    console.error('Ошибка при разблокировке пользователей:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.delete('/api/users', authenticateUser, async (req, res) => {
  try {
    const { userIds } = req.body;
    await User.deleteMany({ _id: { $in: userIds } });
    res.json({ message: 'Пользователи удалены' });
  } catch (error) {
    console.error('Ошибка при удалении пользователей:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.put('/api/users/status', authenticateUser, async (req, res) => {
  try {
    const { userIds, status } = req.body;
    await User.updateMany({ _id: { $in: userIds } }, { status });
    res.status(200).json({ message: 'Статус пользователей успешно обновлен' });
  } catch (error) {
    console.error('Ошибка при обновлении статуса пользователей:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`Сервер запущен на порту ${port}`);
});
