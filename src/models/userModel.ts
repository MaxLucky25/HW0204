import {ObjectId} from "mongodb";

export type EmailConfirmationType = {
    confirmationCode: string;
    expirationDate: Date;
    isConfirmed: boolean;
};


export type UserDBType = {
    _id?: ObjectId;
    id: string;
    login: string;
    password: string;
    email: string;
    createdAt: string;
    emailConfirmation: EmailConfirmationType;
};
// видимая модель из неё исключаем ненужный _id
export type UserViewModel =Omit<UserDBType, '_id' | 'password'>;
// Модели для создания пользователя в них включены только необходимые поля исключая не нужные
export type CreateUserDto = Pick<UserDBType, 'login' | 'password' | 'email'>;