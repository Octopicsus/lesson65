import { MongoClient } from 'mongodb';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import dotenv from 'dotenv';

dotenv.config();

export const MyDBC = 'List';
export const MyDBC_NEW = 'NewList';
const SALT_ROUNDS = 10;

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.b3gzjlp.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
const dbName = 'Lesson65';

const client = new MongoClient(uri);

export const connect = async () => {
    await client.connect();
    const myDB = client.db(dbName);
    return myDB;
};

export async function readUsers() {
    const myDB = await connect();
    const usersCollection = myDB.collection(MyDBC);
    const users = await usersCollection.find({}, { 
        projection: { password: 0 } 
    }).toArray();
  
    return users;
}

export async function getUserForAuth(username) {
    const myDB = await connect();
    const usersCollection = myDB.collection(MyDBC);
    const user = await usersCollection.findOne({ name: username });
    return user;
}

export async function getAllUsersForAuth() {
    const myDB = await connect();
    const usersCollection = myDB.collection(MyDBC);
    const users = await usersCollection.find({}).toArray();
    return users;
}

export async function readNewList() {
    const myDB = await connect();
    const newListCollection = myDB.collection(MyDBC_NEW);
    const newList = await newListCollection.find({}, { 
        projection: { password: 0 } 
    }).toArray();
  
    return newList;
}

export async function saveUser(user) {
    const myDB = await connect();
    const usersCollection = myDB.collection(MyDBC);
    await usersCollection.insertOne(user);
}

export async function registerUser(name, password) {
    const users = await getAllUsersForAuth();
    const existingUser = users.find(user => user.name === name);

    if (existingUser) {
        throw new Error('User with this name already exists');
    }

    const hashedPassword = await hashPassword(password);
    const newUser = {
        id: uuidv4(),
        name,
        password: hashedPassword,
        createdAt: new Date().toISOString()
    };

    await saveUser(newUser);
    return newUser;
}

export async function verifyPassword(plainPassword, hashedPassword) {
    return await bcrypt.compare(plainPassword, hashedPassword);
}

export async function hashPassword(password) {
    return await bcrypt.hash(password, SALT_ROUNDS);
}

export async function copyAllUsersDB() {
    const myDB = await connect();
    const usersCollection = myDB.collection(MyDBC);
    const newListCollection = myDB.collection(MyDBC_NEW);
    const users = await usersCollection.find({}).toArray();
    
    if (users.length === 0) {
        return { message: 'No users to copy', copiedCount: 0 };
    }

    const result = await newListCollection.insertMany(users);
    return { 
        message: 'Users copied successfully', 
        copiedCount: result.insertedCount 
    };
}

export async function deleteUserDB(id) {
    const myDB = await connect();
    const usersCollection = myDB.collection(MyDBC);
    const query = { id: id };
    const result = await usersCollection.deleteOne(query);
    return result;
}

export async function deleteNewListItemDB(id) {
    const myDB = await connect();
    const newListCollection = myDB.collection(MyDBC_NEW);
    const query = { id: id };
    const result = await newListCollection.deleteOne(query);
    return result;
}

export async function cleanAllUsersDB() {
    const myDB = await connect();
    const newListCollection = myDB.collection(MyDBC_NEW);
    const result = await newListCollection.deleteMany({});
    return result;
}

export async function updateNewListUserDB(id, newName) {
    const myDB = await connect();
    const newListCollection = myDB.collection(MyDBC_NEW);

    const existingUser = await newListCollection.findOne({ id: id });
    
    if (!existingUser) {
        return null;
    }

    const updatedUser = {
        ...existingUser,
        name: newName
    };

    const result = await newListCollection.replaceOne(
        { id: id },
        updatedUser
    );

    return result;
}

export async function createUserDB(login, name) {
    const myDB = await connect();
    const usersCollection = myDB.collection(MyDBC);
    const query = { login, name };
    const result = await usersCollection.insertOne(query);
    return result;
}
