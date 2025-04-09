import {Router, Request, Response, NextFunction} from "express";
import { inputCheckErrorsMiddleware } from "../middlewares/validationMiddleware";
import { jwtAuthMiddleware } from "../middlewares/jwtAuthMiddleware";
import {
    confirmationValidators,
    emailResendingValidators,
    loginValidators,
    registrationValidators
} from "../validators/authValidators";
import { authService } from "../services/authService";


export const authRouter = Router();

authRouter.post('/login',
    loginValidators,
    inputCheckErrorsMiddleware,
    async (req: Request, res: Response) => {
        const { loginOrEmail, password } = req.body;
        const tokens = await authService.login(loginOrEmail, password);

        if (!tokens) {
            res.sendStatus(401);
            return;
        }

        res.cookie('refreshToken', tokens.refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'none',
            maxAge: 20 * 1000, // 20 секунд (по спецификации)
        });

        res.status(200).json({ accessToken: tokens.accessToken });
    }
);

authRouter.post('/refresh-token',
    (req: Request, res: Response, next: NextFunction) => {
        if (!req.cookies.refreshToken) {
            res.sendStatus(401);
            return;
        }
        next();
    },
    async (req: Request, res: Response) => {
        const refreshToken = req.cookies.refreshToken;
        const tokens = await authService.refreshTokens(refreshToken);

        if (!tokens) {
            res.sendStatus(401);
            return;
        }

        res.cookie('refreshToken', tokens.refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'none',
            maxAge: 20 * 1000, // 20 секунд
        });

        res.status(200).json({ accessToken: tokens.accessToken });
    }
);


authRouter.post('/logout',
    async (req: Request, res: Response) => {
        const refreshToken = req.cookies.refreshToken;
        if (!refreshToken) {
            res.sendStatus(401);
            return;
        }

        // Отзываем токен
        await authService.revokeRefreshToken(refreshToken);

        res.clearCookie('refreshToken', {
            httpOnly: true,
            secure: true,
            sameSite: 'none',
        });

        res.sendStatus(204);
    }
);

authRouter.get('/me',
    jwtAuthMiddleware,
    async (req: Request, res: Response) => {
        res.status(200).json({
            userId: req.userId,
            login: req.userLogin,
            email: req.userEmail
        });
    }
);

authRouter.post('/registration',
    registrationValidators,
    inputCheckErrorsMiddleware,
    async (req: Request, res: Response): Promise<void>  => {
        const { login, password, email } = req.body;

        const result = await authService.register(login, password, email);
        if (!result) {
            res.status(400).json(result);
            return;
        }
        res.sendStatus(204);
    }
);

authRouter.post('/registration-confirmation',
    confirmationValidators,
    inputCheckErrorsMiddleware,
    async (req: Request, res: Response) => {
        const confirmed = await authService.confirm(req.body.code);
        if (!confirmed) {
            res.status(400);
            return;
        }
        res.sendStatus(204);
    }
);

authRouter.post('/registration-email-resending',
    emailResendingValidators,
    inputCheckErrorsMiddleware,
    async (req: Request, res: Response) => {
        const code = await authService.resendEmail(req.body.email);
        if (!code) {
            res.status(400);
            return;
        }
        res.sendStatus(204);
    }
);
