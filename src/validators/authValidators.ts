import { body } from 'express-validator';
import { userRepository } from '../repositories/userRepository';

// Проверка login
export const loginValidators = [
    body('loginOrEmail')
        .isString().withMessage('loginOrEmail must be a string')
        .notEmpty().withMessage('loginOrEmail is required'),
    body('password')
        .isString().withMessage('Password must be a string')
        .notEmpty().withMessage('Password is required')
];

// Проверка регистрации: login, password, email
export const registrationValidators = [
    // Проверка логина
    body('login')
        .isString().withMessage('Login must be a string')
        .trim()
        .isLength({ min: 3, max: 10 }).withMessage('Login must be between 3 and 10 characters')
        .matches(/^[a-zA-Z0-9_-]*$/).withMessage('Login contains invalid characters')
        .custom(async (login) => {
            // 🔧 Проверка существования логина
            const user = await userRepository.getByLogin(login);
            if (user) {
                throw new Error('Login already exists');
            }
            return true;
        }),
    // Проверка пароля
    body('password')
        .isString().withMessage('Password must be a string')
        .isLength({ min: 6, max: 20 }).withMessage('Password must be between 6 and 20 characters'),
    // Проверка email
    body('email')
        .isString().withMessage('Email must be a string')
        .trim()
        .isEmail().withMessage('Invalid email format')
        .custom(async (email) => {
            // 🔧 Проверка существования email
            const user = await userRepository.getByEmail(email);
            if (user) {
                throw new Error('Email already exists');
            }
            return true;
        })
];

// Проверка кода подтверждения регистрации
export const confirmationValidators = [
    body('code')
        .isString().withMessage('Code must be a string')
        .notEmpty().withMessage('Code is required')
        .custom(async (code) => {
            const user = await userRepository.findByConfirmationCode(code);
            if (!user) {
                throw new Error('Incorrect, expired, or already confirmed code');
            }
            if (user.emailConfirmation.isConfirmed) {
                throw new Error('Incorrect, expired, or already confirmed code');
            }
            if (new Date() > new Date(user.emailConfirmation.expirationDate)) {
                throw new Error('Incorrect, expired, or already confirmed code');
            }
            return true;
        })
];

// Проверка для повторной отправки письма
export const emailResendingValidators = [
    body('email')
        .isString().withMessage('Email must be a string')
        .trim()
        .isEmail().withMessage('Invalid email format')
        .custom(async (email) => {
            const user = await userRepository.getByEmail(email);
            if (!user) {
                throw new Error('User not found');
            }
            if (user.emailConfirmation.isConfirmed) {
                throw new Error('Email already confirmed');
            }
            return true;
        })
];
