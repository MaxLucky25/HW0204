import jwt from 'jsonwebtoken';
import { randomUUID } from "crypto";
import { add } from "date-fns";
import { bcryptService } from "./bcryptService";
import { userRepository } from "../repositories/userRepository";
import { emailService } from "./emailService";
import config from "../utility/config";
import { revokedTokenRepository } from '../repositories/revokedTokenRepository';


export const authService = {
    async login(loginOrEmail: string, password: string):
        Promise<{ accessToken: string, refreshToken: string } | null> {

        const user = await userRepository.getByLoginOrEmail(loginOrEmail);
        if (!user || !user.emailConfirmation.isConfirmed) return null;

        const isValid = await bcryptService.compareHash(password, user.password);

        if (!isValid) return null;

        const accessToken = jwt.sign(
            { userId: user.id, login: user.login, email: user.email },
            config.JWT_SECRET,
            { expiresIn: config.JWT_EXPIRES_IN } as jwt.SignOptions
        );

        const refreshToken = jwt.sign(
            { userId: user.id, deviceId: randomUUID() },
            config.JWT_REFRESH_SECRET,
            { expiresIn: config.JWT_REFRESH_EXPIRES_IN } as jwt.SignOptions
        );

        return { accessToken, refreshToken };
    },

    async revokeRefreshToken(token: string): Promise<void> {
        await revokedTokenRepository.add(token, 20); // 20 секунд как в требованиях
    },

    async isTokenRevoked(token: string): Promise<boolean> {
        return revokedTokenRepository.exists(token);
    },

    async refreshTokens(refreshToken: string): Promise<{ accessToken: string, refreshToken: string } | null> {
        try {
            // Проверяем, не отозван ли токен
            if (await this.isTokenRevoked(refreshToken)) {
                return null;
            }
            // Верифицируем токен
            const decoded = jwt.verify(refreshToken, config.JWT_REFRESH_SECRET) as jwt.JwtPayload;
            // Находим пользователя
            const user = await userRepository.getById(decoded.userId);
            if (!user) return null;

            // Генерируем новые токены с теми же сроками
            const newAccessToken = jwt.sign(
                { userId: user.id, login: user.login, email: user.email },
                config.JWT_SECRET,
                { expiresIn: config.JWT_EXPIRES_IN }as jwt.SignOptions
            );

            const newRefreshToken = jwt.sign(
                { userId: user.id, deviceId: decoded.deviceId },
                config.JWT_REFRESH_SECRET,
                { expiresIn: config.JWT_REFRESH_EXPIRES_IN } as jwt.SignOptions
            );

            // Старый токен помечаем как использованный
            await this.revokeRefreshToken(refreshToken);

            return {
                accessToken: newAccessToken,
                refreshToken: newRefreshToken
            };
        } catch (e) {
            return null;
        }
    },

    async register(login: string, password: string, email: string): Promise<{ userId: string, confirmationCode: string } | null> {
        if (await userRepository.doesExistByLoginOrEmail(login, email)) return null;

        const passwordHash = await bcryptService.generateHash(password);
        const confirmation = generateConfirmation();
        const newUser = {
            id: Date.now().toString(),
            login,
            password: passwordHash,
            email,
            createdAt: new Date().toISOString(),
            emailConfirmation: confirmation,
        };

        await userRepository.create(newUser);
        await emailService.sendRegistrationEmail(email, confirmation.confirmationCode);

        return { userId: newUser.id, confirmationCode: confirmation.confirmationCode };
    },

    async confirm(code: string): Promise<boolean> {
        const user = await userRepository.findByConfirmationCode(code);
        if (!user || user.emailConfirmation.isConfirmed || user.emailConfirmation.expirationDate < new Date()) {
            return false;
        }

        return await userRepository.updateConfirmation(user.id, { isConfirmed: true });
    },

    async resendEmail(email: string): Promise<string | null> {
        const user = await userRepository.getByEmail(email);
        if (!user || user.emailConfirmation.isConfirmed) return null;

        const newConfirmation = generateConfirmation();
        const updated = await userRepository.updateConfirmation(user.id, newConfirmation);
        if (!updated) return null;

        const sent = await emailService.sendRegistrationEmail(email, newConfirmation.confirmationCode);
        return sent ? newConfirmation.confirmationCode : null;
    }
};

function generateConfirmation() {
    return {
        confirmationCode: randomUUID(),
        expirationDate: add(new Date(), { hours: 1, minutes: 30 }),
        isConfirmed: false,
    };
}
