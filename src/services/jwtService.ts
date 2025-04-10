import jwt, { JwtPayload } from 'jsonwebtoken';
import config from '../utility/config';

export const jwtService = {
    createAccessToken(payload: object): string {
        return jwt.sign(payload,
            config.JWT_SECRET,
            { expiresIn: config.JWT_EXPIRES_IN }as jwt.SignOptions
        );
    },

    createRefreshToken(payload: object): string {
        return jwt.sign(payload,
            config.JWT_REFRESH_SECRET,
            { expiresIn: config.JWT_REFRESH_EXPIRES_IN }as jwt.SignOptions
        );
    },

    verifyAccessToken(token: string): JwtPayload | null {
        try {
            return jwt.verify(token, config.JWT_SECRET) as JwtPayload;
        } catch {
            return null;
        }
    },

    verifyRefreshToken(token: string): JwtPayload | null {
        try {
            return jwt.verify(token, config.JWT_REFRESH_SECRET) as JwtPayload;
        } catch {
            return null;
        }
    },

    getRefreshTokenExpiry(token: string): Date | null {
        const payload = this.verifyRefreshToken(token);
        if (!payload?.exp) return null;
        return new Date(payload.exp * 1000);
    }
};
