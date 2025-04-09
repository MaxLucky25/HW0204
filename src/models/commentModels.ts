import { ObjectId } from 'mongodb';

export type CommentDBType = {
    _id?: ObjectId;
    id: string;
    content: string;
    commentatorInfo: {
        userId: string;
        userLogin: string;
    };
    postId: string;
    createdAt: Date;
};

export type CommentViewModel = Omit<CommentDBType, '_id' | 'postId'>;

export type CreateCommentDto = {
    content: string;
};

export type UpdateCommentDto = {
    content: string;
};