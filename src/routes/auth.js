import express from 'express';
import passport from 'passport';
import jwt from 'jsonwebtoken';
import { registerUser } from '../functions/server.js';
import { ensureAuthenticated } from '../middleware/auth.js';

const router = express.Router();
const JWT_SECRET = 'secret-key';
const TOKEN_EXPIRY = '24h';

router.post('/login', (req, res, next) => {
    passport.authenticate('local', (error, user, info) => {
        if (error) {
            return res.render('index', { error: 'Authentication error' });
        }

        if (!user) {
            return res.render('index', { error: info.message || 'Invalid username or password' });
        }

        req.logIn(user, (error) => {
            if (error) {
                return res.render('index', { error: 'Login failed' });
            }

            res.redirect('/protected');
        });
    })(req, res, next);
});

router.post('/logout', (req, res) => {
    req.logout((error) => {
        if (error) {
            return res.status(500).json({ error: 'Logout failed' });
        }

        req.session.destroy(() => {
            res.redirect('/');
        });
    });
});

router.get('/register', (req, res) => {
    res.render('partials/register');
});

router.post('/register', async (req, res) => {
    const { name, password } = req.body;

    try {
        const newUser = await registerUser(name, password);
        req.login(newUser, (error) => {
            if (error) {
                return res.render('partials/register', { error: 'Registration successful but login failed' });
            }
            res.redirect('/');
        });
    } catch (error) {
        res.render('partials/register', { error: error.message });
    }
});

export default router;
