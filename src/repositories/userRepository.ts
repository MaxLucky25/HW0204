import {EmailConfirmationType, UserDBType, UserViewModel} from "../models/userModel";
import { userCollection } from "../db/mongo-db";


export const userRepository = {

    async getById(id: string): Promise<UserDBType | null> {
        return await userCollection.findOne({ id }, { projection: { _id: 0 } });
    },

    async getByLogin(login: string): Promise<UserDBType | null> {
        return await userCollection.findOne({ login }, { projection: { _id: 0 } });
    },

    async getByEmail(email: string): Promise<UserDBType | null> {
        return await userCollection.findOne({ email }, { projection: { _id: 0 } });
    },

    async getByLoginOrEmail(loginOrEmail: string): Promise<UserDBType | null> {
        return (await this.getByLogin(loginOrEmail)) ?? (await this.getByEmail(loginOrEmail));
    },

    async doesExistByLoginOrEmail(login: string, email: string): Promise<UserDBType | null> {
        const byLogin = await this.getByLogin(login);
        if (byLogin) return byLogin;
        return await this.getByEmail(email);
    },
        // Только CRUD операции
        async insert(user: UserDBType): Promise<void> {
            await userCollection.insertOne(user);
        },

    async updateConfirmation(userIdOrEmail: string, updateData: Partial<EmailConfirmationType>): Promise<boolean> {
        const updateFields: Record<string, any> = {};

        if (updateData.confirmationCode !== undefined) {
            updateFields["emailConfirmation.confirmationCode"] = updateData.confirmationCode;
        }
        if (updateData.expirationDate !== undefined) {
            updateFields["emailConfirmation.expirationDate"] = updateData.expirationDate;
        }
        if (updateData.isConfirmed !== undefined) {
            updateFields["emailConfirmation.isConfirmed"] = updateData.isConfirmed;
        }

        const filter = { $or: [ { id: userIdOrEmail }, { email: userIdOrEmail } ] };
        const result = await userCollection.updateOne(filter, { $set: updateFields });
        return result.modifiedCount === 1;
    },

    async findByConfirmationCode(code: string): Promise<UserDBType | null> {
        return await userCollection.findOne({ "emailConfirmation.confirmationCode": code }, { projection: { _id: 0 } });
    },


    async delete(id: string): Promise<boolean> {
        const result = await userCollection.deleteOne({ id: id });
        return result.deletedCount === 1;
    },
};
