import { commentCollection } from '../db/mongo-db';
import { CommentDBType, CommentViewModel, CreateCommentDto, UpdateCommentDto } from '../models/commentModels';
import { getPaginationParams } from '../utility/commonPagination';

export const commentRepository = {
    async getCommentById(id: string): Promise<CommentViewModel | null> {
        const comment = await commentCollection.findOne({ id }, { projection: { _id: 0, postId: 0 } });
        return comment as CommentViewModel | null;
    },

    async create(postId: string,
                 input: CreateCommentDto, commentatorInfo:
                 { userId: string; userLogin: string }): Promise<CommentViewModel> {
        const newComment: CommentDBType = {
            id: Date.now().toString(),
            content: input.content,
            commentatorInfo,
            postId,
            createdAt: new Date(),
        };
        const result = await commentCollection.insertOne(newComment);
        const created = await commentCollection.findOne({ _id: result.insertedId });
        return this.mapToOutput(created!);
    },

    async update(id: string, input: UpdateCommentDto): Promise<boolean> {
        const result = await commentCollection.updateOne(
            { id },
            { $set: { content: input.content } }
        );
        return result.matchedCount === 1;
    },

    async delete(id: string): Promise<boolean> {
        const result = await commentCollection.deleteOne({ id });
        return result.deletedCount === 1;
    },

    async getCommentsByPostId(postId: string, query: any): Promise<any> {
        const { pageNumber, pageSize, sortBy, sortDirection } = getPaginationParams(query);
        const filter = { postId };
        const totalCount = await commentCollection.countDocuments(filter);
        const pagesCount = Math.ceil(totalCount / pageSize);
        const items = await commentCollection.find(filter)
            .sort({ [sortBy]: sortDirection === 'asc' ? 1 : -1 })
            .skip((pageNumber - 1) * pageSize)
            .limit(pageSize)
            .toArray();
        return {
            pagesCount,
            page: pageNumber,
            pageSize,
            totalCount,
            items: items.map(({ _id, postId, ...rest }) => rest) as CommentViewModel[],
        };
    },

    mapToOutput(comment: CommentDBType): CommentViewModel {
        const { _id, postId, ...rest } = comment;
        return rest;
    },
};
