import { revokedTokensCollection } from "../db/mongo-db";
import { addSeconds } from "date-fns";

export const revokedTokenRepository = {
    async add(token: string, expiresInSeconds: number): Promise<boolean> {
        try {
            const result = await revokedTokensCollection.insertOne({
                token,
                expiresAt: addSeconds(new Date(), expiresInSeconds)
            });
            return result.acknowledged;
        } catch (e) {
            console.error("Failed to revoke token", e);
            return false;
        }
    },

    async exists(token: string): Promise<boolean> {
        try {
            const count = await revokedTokensCollection.countDocuments({ token });
            return count > 0;
        } catch (e) {
            console.error("Failed to check revoked token", e);
            return false;
        }
    },

    async remove(token: string): Promise<boolean> {
        try {
            const result = await revokedTokensCollection.deleteOne({ token });
            return result.deletedCount > 0;
        } catch (e) {
            console.error("Failed to remove revoked token", e);
            return false;
        }
    }
};