import { Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv';

// Загружаем переменные окружения из .env
dotenv.config();

// Достаём логин и пароль из переменных окружения
const ADMIN_LOGIN = process.env.ADMIN_LOGIN;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

export const authMiddleware = (
    req: Request,
    res: Response,
    next: NextFunction
): void => {
    // Получаем заголовок авторизации
    const authHeader = req.headers.authorization;

    // Проверяем, что заголовок есть и начинается с 'Basic '
    if (typeof authHeader !== 'string' || !authHeader.startsWith('Basic ')) {
        res.sendStatus(401); // Unauthorized
        return;
    }

    try {
        // Извлекаем base64-строку (вторую часть после 'Basic ')
        const base64Credentials = authHeader.split(' ')[1];

        // Декодируем base64 в строку формата "логин:пароль"
        const decodedCredentials = Buffer.from(base64Credentials, 'base64').toString('utf-8');

        // Разбиваем строку на логин и пароль
        const [login, password] = decodedCredentials.split(':');

        // Проверяем логин и пароль по отдельности
        if (login === ADMIN_LOGIN && password === ADMIN_PASSWORD) {
            next(); // Доступ разрешён — идём дальше
        } else {
            res.sendStatus(401); // Неверные логин или пароль
        }
    } catch (error) {
        res.sendStatus(401); // Ошибка при обработке — считаем запрос неавторизованным
    }
};
