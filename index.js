import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import 'dotenv/config'
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

mongoose.connect(process.env.MONGO_URL)
  .then(() => {
    console.log('Database connected');
  })
  .catch((e) => {
    console.log(e);
  });

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
});

const User = mongoose.model('User', userSchema);

const SECRET_KEY = process.env.SECRET_KEY; // Use a strong secret key in production

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
      return res.status(403).send('A token is required for authentication');
    }
  
    const token = authHeader.split(' ')[1]; // Extract the token from the Bearer string
    if (!token) {
      return res.status(403).send('A token is required for authentication');
    }
  
    try {
      const decoded = jwt.verify(token, SECRET_KEY);
      req.user = decoded;
    } catch (err) {
      return res.status(401).send('Invalid Token');
    }
    return next();
  };
  
// Routes
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.send({ message: 'User already registered' });
    }
    const hashedPassword = bcrypt.hashSync(password, 10);
    const user = new User({
      name,
      email,
      password: hashedPassword,
    });
    await user.save();
    res.send({ message: 'Successfully Registered, Please login now.' });
  } catch (err) {
    res.status(500).send(err);
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (user && bcrypt.compareSync(password, user.password)) {
      const token = jwt.sign(
        { user_id: user._id, email },
        SECRET_KEY,
        { expiresIn: '2h' },
      );
      return res.send({ message: 'Login Successful', token });
    }
    res.send({ message: 'Invalid email or password' });
  } catch (err) {
    res.status(500).send(err);
  }
});

// Protected route example
app.get('/protected', verifyToken, (req, res) => {
  res.send('This is a protected route');
});


app.listen(9002, () => {
  console.log('BE started at port 9002');
});
