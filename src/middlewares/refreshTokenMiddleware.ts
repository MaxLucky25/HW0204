import { Request, Response, NextFunction } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';
import config from '../utility/config';
import { revokedTokenRepository } from '../repositories/revokedTokenRepository';

export const refreshTokenMiddleware = async (req: Request, res: Response, next: NextFunction) => {
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
        res.sendStatus(401);
        return;
    }

    try {
        const decoded = jwt.verify(refreshToken, config.JWT_REFRESH_SECRET) as JwtPayload;

        const isRevoked = await revokedTokenRepository.isRevoked(refreshToken);
        if (isRevoked) {
            res.sendStatus(401);
            return;
        }

        // Добавим все поля как и в jwtAuthMiddleware
        req.userId = decoded.userId;
        req.userLogin = decoded.login;
        req.userEmail = decoded.email;
        req.refreshToken = refreshToken;

        next();
    } catch (e) {
        res.sendStatus(401);
        return;
    }
};
