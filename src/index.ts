import app from './app';
import { connectToDB } from './db/mongo-db';

const PORT = process.env.PORT || 3000;


const start = async () => {
    try {
        const isConnected = await connectToDB();
        if (!isConnected) {
            console.error('Failed to connect to database');
            process.exit(1);
        }
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
        });
    } catch (e) {
        console.error('Fatal error:', e);
        process.exit(1);
    }
};

start();