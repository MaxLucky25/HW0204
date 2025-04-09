import { commentRepository } from "../repositories/commentRepository";
import {CommentViewModel, CreateCommentDto, UpdateCommentDto} from "../models/commentModels";
import { postRepository } from "../repositories/postRepository";


export const commentService = {
    async createComment(postId: string, input: CreateCommentDto, commentatorInfo: {
        userId: string;
        userLogin: string
    }): Promise<CommentViewModel | null> {
        // Проверяем существование поста
        const post = await postRepository.getById(postId);
        if (!post) return null;

        // Создаём комментарий
        return await commentRepository.create(postId, input, commentatorInfo);
    },

    async updateComment(commentId: string, input: UpdateCommentDto): Promise<boolean> {
        return await commentRepository.update(commentId, input);
    },

    async deleteComment(commentId: string): Promise<boolean> {
        return await commentRepository.delete(commentId);
    },

    async getCommentById(commentId: string) {
        return await commentRepository.getCommentById(commentId);
    },

    async getCommentsByPostId(postId: string, query: any) {
        const post = await postRepository.getById(postId);
        if (!post) return null;
        return await commentRepository.getCommentsByPostId(postId, query);
    }
};
