import express from 'express';
import { getAllUsersForAuth, readNewList } from '../functions/server.js';
import { ensureAuthenticated } from '../middleware/auth.js';

const router = express.Router();

router.get('/', (req, res) => {
    res.render('index');
});

router.get('/protected', ensureAuthenticated(), async (req, res) => {
    try {
        const allUsers = await getAllUsersForAuth({ 
            sort: { name: 1 }
        });

        const newList = await readNewList();
        
        const usersData = allUsers.map(user => ({
            id: user.id,
            name: user.name
        }));
        
        const newListData = newList.map(item => ({
            id: item.id || item._id,
            name: item.name || item.login
        }));

        res.render('partials/protected', { 
            user: req.user, 
            users: usersData, 
            newList: newListData
        });
    } catch (error) {
        console.error('Error in protected route:', error);
        res.status(500).send('Server Error');
    }
});

export default router;
