import {Router, Request, Response,} from "express";
import { inputCheckErrorsMiddleware } from "../middlewares/validationMiddleware";
import { jwtAuthMiddleware } from "../middlewares/jwtAuthMiddleware";
import {
    confirmationValidators,
    emailResendingValidators,
    loginValidators,
    registrationValidators
} from "../validators/authValidators";
import { authService } from "../services/authService";
import { userRepository } from "../repositories/userRepository";
import {refreshTokenMiddleware} from "../middlewares/refreshTokenMiddleware";


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
            sameSite: 'strict',
        });

        res.status(200).json({ accessToken: tokens.accessToken });
    }
);

authRouter.post('/refresh-token',
    refreshTokenMiddleware,
    async (req: Request, res: Response) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken){
        res.sendStatus(401);
        return;
    }

    const tokens = await authService.refreshTokens(refreshToken);
    if (!tokens) {
        res.sendStatus(401);
        return;
    }

    res.cookie('refreshToken', tokens.refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
    });

    res.status(200).json({ accessToken: tokens.accessToken });
});


authRouter.post('/logout',
    refreshTokenMiddleware,
    async (req: Request, res: Response) => {
    const refreshToken = req.cookies.refreshToken;
    if (refreshToken) {
        await authService.revokeRefreshToken(refreshToken);
    }

    res.clearCookie('refreshToken');
    res.sendStatus(204);
});

authRouter.get('/me',
    jwtAuthMiddleware,
    async (req: Request, res: Response) => {
    const userId = req.userId!;
    const user = await userRepository.getById(userId);
    if (!user){
        res.sendStatus(401);
        return;
    }

    res.status(200).send({
        email: user.email,
        login: user.login,
        userId: user.id.toString(),
    });
});

authRouter.post('/registration',
    registrationValidators,
    inputCheckErrorsMiddleware,
    async (req: Request, res: Response): Promise<void>  => {
        const { login, password, email } = req.body;

        const result = await authService.register(login, password, email);
        if (!result) {
            res.status(400);
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
