import express from 'express';
import passport from 'passport';
import jwt from 'jsonwebtoken';
import { registerUser, getAllUsersForAuth, readNewList } from '../functions/server.js';
import { ensureAuthenticated } from '../middleware/auth.js';

const router = express.Router();
const JWT_SECRET = 'secret-key';
const TOKEN_EXPIRY = '24h';

router.post('/login', (req, res, next) => {
    passport.authenticate('local', (error, user, info) => {
        if (error) {
            return res.status(500).json({ error: 'Authentication error' });
        }

        if (!user) {
            return res.status(401).json({ error: info.message || 'Invalid credentials' });
        }

        req.logIn(user, (error) => {
            if (error) {
                return res.status(500).json({ error: 'Login error' });
            }

            const token = jwt.sign({ id: user.id, name: user.name }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
            res.json({
                token,
                user: { id: user.id, name: user.name },
                expiresIn: TOKEN_EXPIRY
            });
        });
    })(req, res, next);
});

router.post('/register', async (req, res) => {
    const { name, password } = req.body;

    try {
        const newUser = await registerUser(name, password);
        req.logIn(newUser, (error) => {
            if (error) {
                return res.status(500).json({ error: 'Registration successful but login failed' });
            }

            const token = jwt.sign({ id: newUser.id, name: newUser.name }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
            res.json({
                token,
                user: { id: newUser.id, name: newUser.name },
                expiresIn: TOKEN_EXPIRY
            });
        });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

router.post('/logout', ensureAuthenticated(true), (req, res) => {
    req.logout((error) => {
        if (error) {
            return res.status(500).json({ error: 'Logout failed' });
        }
        req.session.destroy(() => {
            res.json({ message: 'Logged out successfully' });
        });
    });
});

router.get('/protected', ensureAuthenticated(true), (req, res) => {
    res.json({ message: 'This is protected data', user: req.user });
});

router.post('/verify-token', async (req, res) => {
    const { token } = req.body;

    if (!token) {
        return res.status(400).json({ error: 'Token required' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        res.json({ valid: true, user: { id: decoded.id, name: decoded.name } });
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired' });
        }
        res.status(403).json({ error: 'Invalid token' });
    }
});

router.get('/users', ensureAuthenticated(true), async (req, res) => {
    try {
        const users = await getAllUsersForAuth({ sort: { name: 1 } });
        const usersData = users.map(user => ({
            id: user.id,
            name: user.name
        }));
        
        res.json({
            users: usersData
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

router.get('/newlist', ensureAuthenticated(true), async (req, res) => {
    try {
        const newListItems = await readNewList();
        const newListData = newListItems.map(item => ({
            id: item.id || item._id,
            name: item.name || item.login
        }));
        
        res.json({
            items: newListData
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

export default router;
