export function ensureAuthenticated(returnJson = false) {
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
