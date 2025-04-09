import {ObjectId} from "mongodb";

export type PostDBType = {
    _id?: ObjectId;
    id: string;
    title: string;
    shortDescription: string;
    content: string;
    blogId: string;
    blogName: string;
    createdAt: Date;
};
// видимая модель из неё исключаем ненужный _id
export type PostViewModel =Omit<PostDBType, '_id'>;
// Модели для создания и обновления постов в них включены только необходимые поля исключая не нужные
export type CreatePostDto = Pick<PostDBType, 'title' | 'shortDescription' | 'content' | 'blogId'>;
export type UpdatePostDto = Pick<PostDBType, 'title' | 'shortDescription' | 'content' | 'blogId'>;