import {ObjectId} from "mongodb";

export type BlogDBType = {
    _id?: ObjectId;
    id: string;
    name: string;
    description: string;
    websiteUrl: string;
    createdAt: Date;
    isMembership: boolean;
};
// видимая модель из неё исключаем ненужный _id
export type BlogViewModel = Omit<BlogDBType, '_id'>;
// Модели для создания и обновления блогов в них включены только необходимые поля исключая не нужные
export type CreateBlogDto = Pick<BlogDBType, 'name' | 'description' | 'websiteUrl'>;
export type UpdateBlogDto = Pick<BlogDBType, 'name' | 'description' | 'websiteUrl'>;