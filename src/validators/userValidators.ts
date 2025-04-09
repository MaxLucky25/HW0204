import {body} from "express-validator";


export const userValidators = [
    body('login')
        .isString().withMessage('Login must be a string')
        .trim()
        .isLength({ min: 3, max: 10 }).withMessage('Login length must be between 3 and 10')
        .matches(/^[a-zA-Z0-9_-]*$/).withMessage('Login contains invalid characters'),
    body('password')
        .isString().withMessage('Password must be a string')
        .isLength({ min: 6, max: 20 }).withMessage('Password length must be between 6 and 20'),
    body('email')
        .isString().withMessage('Email must be a string')
        .isEmail().withMessage('Invalid email format'),
];