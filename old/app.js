import express from "express"
import { MongoClient, ObjectId } from 'mongodb'
import cors from 'cors'
import dotenv from 'dotenv'

dotenv.config();

const PORT = 3000
const app = express()
app.use(cors())
app.use(express.json())

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.b3gzjlp.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`
const dbName = 'Octo'

const client = new MongoClient(uri)

const connect = async () => {
    await client.connect()
    const myDB = client.db(dbName)
    return myDB
}

app.get('/users', async (req, res) => {
    try {
        const myDB = await connect()
        const usersCollection = myDB.collection('users')
        const result = await usersCollection.find().toArray()

        return res.json(result)
    } catch (error) {
        return res.json(error)
    }
})

app.post('/users', async (req, res) => {
    const { login, name } = req.body
    const myDB = await connect()
    const usersCollection = myDB.collection('users')
    try {
        const result = await usersCollection.insertOne({ login, name })
        res.json(result)
    } catch (error) {
        res.error(error)
    }
})

app.patch('/users', async (req, res) => {
    const { id, login } = req.body
    const myDB = await connect()
    const usersCollection = myDB.collection('users')

    const query = { _id: new ObjectId(id) }
    const update = { $set: { login, email:'test@test.com'} }
    const result = await usersCollection.updateOne(query, update)

    res.json(result)
})

app.delete('/users', async (req, res) => {
    try {
         const { id } = req.body 
        const myDB = await connect()
        const usersCollection = myDB.collection('users')
        
        const query = { _id: new ObjectId(id) }
        const result = await usersCollection.deleteOne(query)
        
      if (result.deletedCount === 1) {
            res.json({ message: 'User deleted successfully', deletedCount: result.deletedCount })
        } else {
            res.status(404).json({ message: 'User not found' })
        }
    } catch (error) {
           res.error(error)
    }
})

app.post('/collection', async (req, res) => {
    const { collectionName } = req.body
    const myDB = await connect()
    const allCollections = await myDB.listCollections().toArray()
    const collectionsName = allCollections.map(collection => collection.name)

    if (!collectionsName.includes(collectionName)) {
        await myDB.createCollection(collectionName)
        res.send('New collection created')
    } else {
        res.send('collection already exists')
    }
})


app.listen(PORT, () => console.log(`Server start working, ${PORT}`))