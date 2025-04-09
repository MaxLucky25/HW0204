import { Router } from 'express';
import {blogCollection, commentCollection, postCollection, userCollection} from "../db/mongo-db";


export const testingRouters = Router();

testingRouters.delete('/all-data', async (req, res) => {
    await blogCollection.deleteMany({});
    await postCollection.deleteMany({});
    await userCollection.deleteMany({});
    await commentCollection.deleteMany({})
    res.sendStatus(204);
});

