import {Request, Response, Router} from "express";
import {authMiddleware} from "../middlewares/authMiddleware";
import {userValidators} from "../validators/userValidators";
import { userService } from "../services/userService";
import { inputCheckErrorsMiddleware } from "../middlewares/validationMiddleware";


export const userRouter = Router();

userRouter.get('/',
    authMiddleware,
    async (req: Request, res: Response) => {
        const result = await userService.getUsers(req.query);
        res.status(200).json(result);
    });

userRouter.post('/',
    authMiddleware,
    userValidators,
    inputCheckErrorsMiddleware,
    async (req: Request, res: Response) => {
        const result = await userService.createUserByAdmin(req.body);
        result ? res.sendStatus(204).json(result) : res.sendStatus(404);
    });

userRouter.delete('/:id',
    authMiddleware,
    async (req: Request, res: Response) => {
        const deleted = await userService.deleteUser(req.params.id);
        deleted ? res.sendStatus(204) : res.sendStatus(404);
    });

