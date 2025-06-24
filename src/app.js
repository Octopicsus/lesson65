import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import session from 'express-session';
import dotenv from 'dotenv';
import {
    connect,
    MyDBC,
    MyDBC_NEW,
    getUserForAuth,
    getAllUsersForAuth,
    readNewList,
    saveUser,
    registerUser,
    verifyPassword,
    hashPassword,
    copyAllUsersDB,
    deleteUserDB,
    deleteNewListItemDB,
    cleanAllUsersDB,
    updateNewListUserDB,
    createUserDB
} from './functions/server.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = 3000;
const JWT_SECRET = 'secret-key';
const TOKEN_EXPIRY = '24h';



passport.use(new LocalStrategy({
    usernameField: 'username',
    passwordField: 'password'
}, async (username, password, done) => {
    try {
        const user = await getUserForAuth(username);

        if (!user) {
            return done(null, false, { message: 'Invalid username or password' });
        }

        const isValidPassword = await verifyPassword(password, user.password);
        if (!isValidPassword) {
            return done(null, false, { message: 'Invalid username or password' });
        }

        return done(null, user);
    } catch (error) {

        return done(error);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const users = await getAllUsersForAuth();
        const user = users.find(user => user.id === id);

        if (!user) {
            return done(null, false);
        }

        done(null, user);
    } catch (error) {
        done(error);
    }
});

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

function ensureAuthenticated(returnJson = false) {
    return (req, res, next) => {
        if (req.isAuthenticated()) {
            return next();
        }

        if (returnJson) {
            return res.status(401).json({ error: 'Authentication required' });
        } else {
            return res.redirect('/');
        }
    };
}

app.get('/', (req, res) => {
    res.render('index');
});

app.post('/auth/login', (req, res, next) => {
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

app.post('/auth/logout', (req, res) => {
    req.logout((error) => {
        if (error) {
            return res.status(500).json({ error: 'Logout failed' });
        }

        req.session.destroy(() => {
            res.redirect('/');
        });
    });
});

app.get('/auth/register', (req, res) => {
    res.render('partials/register');
});

app.post('/auth/register', async (req, res) => {
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

app.post('/api/login', (req, res, next) => {
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

app.post('/api/register', async (req, res) => {
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

app.post('/api/logout', ensureAuthenticated(true), (req, res) => {
    req.logout((error) => {
        if (error) {
            return res.status(500).json({ error: 'Logout failed' });
        }
        req.session.destroy(() => {
            res.json({ message: 'Logged out successfully' });
        });
    });
});

app.get('/protected', ensureAuthenticated(), async (req, res) => {
    const allUsers = await getAllUsersForAuth();
    if (allUsers.length === 0) {

        req.logout((err) => {
            if (err) console.error('Logout error:', err);
            req.session.destroy(() => {
                return res.redirect('/');
            });
        });
        return;
    }

    const usersData = allUsers.map(user => ({
        id: user.id,
        name: user.name,
        createdAt: user.createdAt
    }));
    const newList = await readNewList();
    const newListData = newList.map(item => ({
        id: item.id || item._id,
        name: item.name || item.login,
        createdAt: item.createdAt
    }));

    res.render('partials/protected', { user: req.user, users: usersData, newList: newListData });
});

app.get('/api/protected', ensureAuthenticated(true), (req, res) => {
    res.json({ message: 'This is protected data', user: req.user });
});

app.post('/api/verify-token', async (req, res) => {
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

app.get('/api/users', ensureAuthenticated(true), async (req, res) => {
    const users = await getAllUsersForAuth();
    const usersData = users.map(user => ({
        id: user.id,
        name: user.name,
        createdAt: user.createdAt
    }));
    res.json(usersData);
});

app.post('/users', async (req, res) => {
    try {
        const { login, name } = req.body
        const result = await createUserDB(login, name)
        res.json(result)
    } catch (error) {
        res.status(500).json({ error: error.message })
    }
})

app.delete('/users', async (req, res) => {
    try {
        const { id } = req.body
        const result = await deleteUserDB(id)

        if (result.deletedCount === 1) {
            res.json({ message: 'User deleted successfully', deletedCount: result.deletedCount })
        } else {
            res.status(404).json({ message: 'User not found' })
        }
    } catch (error) {
        res.status(500).json({ error: error.message })
    }
})

app.delete('/newlist', async (req, res) => {
    try {
        const { id } = req.body
        const result = await deleteNewListItemDB(id)

        if (result.deletedCount === 1) {
            res.json({ message: 'Item deleted successfully', deletedCount: result.deletedCount })
        } else {
            res.status(404).json({ message: 'Item not found' })
        }
    } catch (error) {
        res.status(500).json({ error: error.message })
    }
})

app.post('/copy-users', async (req, res) => {
    try {
        const result = await copyAllUsersDB()
        res.json(result)
    } catch (error) {
        res.status(500).json({ error: error.message })
    }
})

app.put('/newlist', async (req, res) => {
    try {
        const { id, newName } = req.body
        const result = await updateNewListUserDB(id, newName)

        if (!result) {
            return res.status(404).json({ message: 'User not found' })
        }

        if (result.modifiedCount === 1) {
            res.json({ message: 'User updated successfully', modifiedCount: result.modifiedCount })
        } else {
            res.status(404).json({ message: 'User not found or no changes made' })
        }
    } catch (error) {
        res.status(500).json({ error: error.message })
    }
})

app.delete('/clean-newlist', async (req, res) => {
    try {
        const result = await cleanAllUsersDB()
        res.json({
            message: 'All items deleted successfully',
            deletedCount: result.deletedCount
        })
    } catch (error) {
        res.status(500).json({ error: error.message })
    }
})

app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
});