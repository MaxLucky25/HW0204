import { userRepository } from '../repositories/userRepository';
import { userQueryRepository } from '../repositories/userQueryRepository';
import { CreateUserDto, UserViewModel } from '../models/userModel';
import bcrypt from 'bcryptjs';


export const userService = {

    async getUsers(query: any) {
        return await userQueryRepository.getUsers(query);
    },

    async deleteUser(id: string): Promise<boolean> {
        return await userRepository.delete(id);
    },

    async createUserByAdmin(input: CreateUserDto): Promise<UserViewModel | null > {
        const passwordHash = await bcrypt.hash(input.password, 10);
        return await userRepository.createUserByAdmin(input, passwordHash);
    }
};