import { body } from 'express-validator';


export const blogValidators = [
    body('name')
        .isString().withMessage('Name must be a string')
        .trim()
        .notEmpty().withMessage('Name is required')
        .isLength({ max: 15 }).withMessage('Max length 15'),

    body('description')
        .isString().withMessage('Description must be a string')
        .trim()
        .notEmpty().withMessage('Description is required')
        .isLength({ max: 500 }).withMessage('Max length 500'),

    body('websiteUrl')
        .isString().withMessage('Website URL must be a string')
        .trim()
        .notEmpty().withMessage('Website URL is required')
        .isLength({ max: 100 }).withMessage('Max length 100')
        .matches(/^https:\/\/([a-zA-Z0-9_-]+\.)+[a-zA-Z0-9_-]+(\/[a-zA-Z0-9_-]+)*\/?$/)
        .withMessage('Invalid URL format')
];

