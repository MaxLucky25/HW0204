import {CreateUserDto, EmailConfirmationType, UserDBType, UserViewModel} from "../models/userModel";
import { userCollection } from "../db/mongo-db";
import { emailService } from "../services/emailService";
import {randomUUID} from "crypto";

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

    async createUserByAdmin(input: CreateUserDto, passwordHash: string): Promise<UserViewModel | null> {

        const newUser: UserDBType = {
            id: Date.now().toString(),
            login: input.login,
            email: input.email,
            password: passwordHash,
            createdAt: new Date().toISOString(),
            emailConfirmation: {
                confirmationCode: randomUUID(),
                expirationDate: new Date(),
                isConfirmed: true,
            },
        };

        return await userRepository.create(newUser);
    },

    async create(user: UserDBType): Promise<UserViewModel | null > {
            await userCollection.insertOne(user);
        // Отправляем письмо с подтверждением
        if (!user.emailConfirmation.isConfirmed) {
            await emailService.sendRegistrationEmail(user.email, user.emailConfirmation.confirmationCode);
        }
        return this.mapToOutput(user);
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

    mapToOutput(user: UserDBType): UserViewModel {
        const { _id, password, ...rest } = user;
        return rest;
    }
};
