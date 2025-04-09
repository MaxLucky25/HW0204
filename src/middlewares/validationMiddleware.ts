import { Request, Response, NextFunction } from 'express';
import { validationResult } from 'express-validator';

type ErrorResponse = {
    message: string;
    field: string;
};
// прослойка для сбора ошибок валидатора
export const inputCheckErrorsMiddleware = (
    req: Request,
    res: Response,
    next: NextFunction
): void => {
    const errors = validationResult(req);
    // создаём через конструктор функцию которая мапит все ошибки в массив
    if (!errors.isEmpty()) {
        const errorsMap = new Map<string, ErrorResponse>();

        errors.array().forEach((error) => {
            if ('path' in error && error.msg && !errorsMap.has(error.path)) {
                errorsMap.set(error.path, {
                    message: error.msg,
                    field: error.path
                });
            }
        });

        res.status(400).json({ errorsMessages: Array.from(errorsMap.values()) });
        return;
    }

    next();
};