import express from 'express';
import {
    createUserDB,
    deleteUserDB,
    copyAllUsersDB,
    getAllUsersForAuth
} from '../functions/server.js';

const router = express.Router();

router.post('/', async (req, res) => {
    try {
        const { login, name } = req.body
        const result = await createUserDB(login, name)
        res.json(result)
    } catch (error) {
        res.status(500).json({ error: error.message })
    }
});

router.delete('/', async (req, res) => {
    try {
        const { id } = req.body;
        const result = await deleteUserDB(id);

        if (result.deletedCount === 1) {
            const remainingUsers = await getAllUsersForAuth();
            const shouldRedirect = remainingUsers.length === 0;
            
            res.json({ 
                message: 'User deleted successfully', 
                deletedCount: result.deletedCount,
                shouldRedirect: shouldRedirect
            });
        } else {
            res.status(404).json({ message: 'User not found' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

router.post('/copy', async (req, res) => {
    try {
        const result = await copyAllUsersDB()
        res.json(result)
    } catch (error) {
        res.status(500).json({ error: error.message })
    }
});

export default router;
