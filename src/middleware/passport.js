import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import {
    getUserForAuth,
    getAllUsersForAuth,
    verifyPassword
} from '../functions/server.js';

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
            if (users.length > 0) {
                const tempUser = {
                    id: id,
                    name: 'Deleted User (Session Active)',
                    login: 'deleted-user-session'
                };
                return done(null, tempUser);
            } else {
                return done(null, false);
            }
        }

        return done(null, user);
    } catch (error) {
        done(error);
    }
});

export default passport;
