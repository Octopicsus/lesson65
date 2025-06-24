import express from 'express';
import {
    deleteNewListItemDB,
    updateNewListUserDB,
    cleanAllUsersDB
} from '../functions/server.js';

const router = express.Router();

router.delete('/', async (req, res) => {
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
});

router.put('/', async (req, res) => {
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
});

router.delete('/clean', async (req, res) => {
    try {
        const result = await cleanAllUsersDB();
        res.json({
            message: 'All items deleted successfully',
            deletedCount: result.deletedCount
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

export default router;
