import dotenv from "dotenv";
import {Collection, Db, MongoClient } from "mongodb";
import {BlogDBType} from "../models/blogModels";
import {PostDBType} from "../models/postModels";
import {UserDBType} from "../models/userModel";
import {CommentDBType} from "../models/commentModels";
import {RevokedTokenDBType} from "../models/revokedTokenModel";

// Подключаем библиотеку
dotenv.config()


export let db: Db;
export let blogCollection: Collection<BlogDBType>;
export let postCollection: Collection<PostDBType>;
export let userCollection: Collection<UserDBType>;
export let commentCollection: Collection<CommentDBType>;
export let revokedTokensCollection: Collection<RevokedTokenDBType>;

// Объявляем путь подключения к базе данных
const mongoURI = process.env.MONGO_URL || "mongodb://0.0.0.0:27017";
const dbName = 'Cluster0103';

// саздаём нового клиента для подключения
const client = new MongoClient(mongoURI, {
    serverSelectionTimeoutMS: 15000,
    tls: true,
    tlsAllowInvalidCertificates: true,
});

// подключение к базе данных
export const connectToDB = async () => {
    try{
        await client.connect();
        db = client.db(dbName);

        // Объявляем эндпоинты
        blogCollection= db.collection<BlogDBType>("blogs");
        await blogCollection.createIndex({id:1}, {unique:true});

        postCollection= db.collection<PostDBType>("posts");
        await postCollection.createIndex({id:1}, {unique:true});

        userCollection= db.collection<UserDBType>("users");
        await userCollection.createIndex({id:1}, {unique:true});

        commentCollection = db.collection<CommentDBType>("comments");
        await commentCollection.createIndex({ id: 1 }, { unique: true });

        revokedTokensCollection = db.collection<RevokedTokenDBType>("revokedTokens");
        await revokedTokensCollection.createIndex({ token: 1 }, { unique: true });
        await revokedTokensCollection.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });

        console.log("Successfully connected to MongoDB");
        return true;
    }catch(e){
        console.error('Connection to MongoDb failed', e);
        await client.close();
        return false;
    }
};