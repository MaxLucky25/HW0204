import { postCollection } from '../db/mongo-db';
import { PostViewModel } from '../models/postModels';
import { getPaginationParams } from '../utility/commonPagination';

export const postQueryRepository = {
    async getPosts(query: any): Promise<any> {
        const { pageNumber, pageSize, sortBy, sortDirection } = getPaginationParams(query);
        const filter = {};

        const totalCount = await postCollection.countDocuments(filter);
        const pagesCount = Math.ceil(totalCount / pageSize);
        const items = await postCollection.find(filter)
            .sort({ [sortBy]: sortDirection === 'asc' ? 1 : -1 })
            .skip((pageNumber - 1) * pageSize)
            .limit(pageSize)
            .toArray();

        return {
            pagesCount,
            page: pageNumber,
            pageSize,
            totalCount,
            items: items.map(({ _id, ...rest }) => rest) as PostViewModel[],
        };
    },

    async getPostsByBlogId(blogId: string, query: any): Promise<any> {
        const { pageNumber, pageSize, sortBy, sortDirection } = getPaginationParams(query);
        const filter = { blogId };
        const totalCount = await postCollection.countDocuments(filter);
        const pagesCount = Math.ceil(totalCount / pageSize);
        const items = await postCollection.find(filter)
            .sort({ [sortBy]: sortDirection === 'asc' ? 1 : -1 })
            .skip((pageNumber - 1) * pageSize)
            .limit(pageSize)
            .toArray();

        return {
            pagesCount,
            page: pageNumber,
            pageSize,
            totalCount,
            items: items.map(({ _id, ...rest }) => rest) as PostViewModel[],
        };
    }
};
