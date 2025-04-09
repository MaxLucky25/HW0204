import bcrypt from 'bcryptjs';

export const bcryptService = {
    async generateHash(password: string): Promise<string> {
        const saltRounds = 10;
        return await bcrypt.hash(password, saltRounds);
    },
    async compareHash(password: string, hash: string): Promise<boolean> {
        return await bcrypt.compare(password, hash);
    }
};
