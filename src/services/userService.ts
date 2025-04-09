import { userRepository } from '../repositories/userRepository';
import { userQueryRepository } from '../repositories/userQueryRepository';
import {CreateUserDto, UserDBType} from '../models/userModel';
import bcrypt from 'bcryptjs';
import { randomUUID } from 'crypto';


export const userService = {

    async getUsers(query: any) {
        return await userQueryRepository.getUsers(query);
    },

    async deleteUser(id: string): Promise<boolean> {
        return await userRepository.delete(id);
    },

    async createUserByAdmin(input: CreateUserDto) {
        if (await userRepository.doesExistByLoginOrEmail(input.login, input.email)) {
            return null;
        }

        const user: UserDBType = {
            id: Date.now().toString(),
            login: input.login,
            email: input.email,
            password: await bcrypt.hash(input.password, 10),
            createdAt: new Date().toISOString(),
            emailConfirmation: {
                confirmationCode: randomUUID(),
                expirationDate: new Date(),
                isConfirmed: true // Админ создает подтвержденного пользователя
            }
        };

        await userRepository.insert(user);
    }
};