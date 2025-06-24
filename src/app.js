import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import session from 'express-session';
import dotenv from 'dotenv';
import passport from './middleware/passport.js';

import authRoutes from './routes/auth.js';
import apiRoutes from './api/api.js';
import usersRoutes from './routes/users.js';
import newlistRoutes from './routes/newlist.js';
import pagesRoutes from './routes/pages.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = 3000;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(session({
    secret: 'passport-secret-key',
    resave: false,
    saveUninitialized: false,
}));

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '..', 'public')));
app.use('/src', express.static(path.join(__dirname, '.')));

app.use(passport.initialize());
app.use(passport.session());

app.use('/', pagesRoutes);
app.use('/auth', authRoutes);
app.use('/api', apiRoutes);
app.use('/users', usersRoutes);
app.use('/newlist', newlistRoutes);

app.post('/copy-users', async (req, res) => {
    try {
        const { copyAllUsersDB } = await import('./functions/server.js');
        const result = await copyAllUsersDB();
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
});