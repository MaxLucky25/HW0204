import { userCollection } from "../db/mongo-db";
import {getUsersPaginationParams} from "../utility/userPagination";


export const userQueryRepository = {
    async getUsers(query: any): Promise<any>{
        const {pageNumber, pageSize, sortBy, sortDirection, searchLoginTerm, searchEmailTerm} = getUsersPaginationParams(query);

    const filter: any = {};
    const orConditions: any[] = [];
        if (searchLoginTerm) {
            orConditions.push({ login: { $regex: searchLoginTerm, $options: "i" } });
        }

        if (searchEmailTerm) {
            orConditions.push({ email: { $regex: searchEmailTerm, $options: "i" } });
        }

        if (orConditions.length > 0) {
            filter.$or = orConditions;
        }

        const totalCount = await userCollection.countDocuments(filter);
        const pagesCount = Math.ceil(totalCount / pageSize);
        const items = await userCollection.find(filter)
            .sort({ [sortBy]: sortDirection === 'asc' ? 1 : -1 })
            .skip((pageNumber - 1) * pageSize)
            .limit(pageSize)
            .toArray();

        return {
            pagesCount,
            page: pageNumber,
            pageSize,
            totalCount,
            items: items.map(({_id,password, ...rest}) => rest),
        };
    },
};