import { blogCollection } from '../db/mongo-db';
import { BlogViewModel } from '../models/blogModels';
import { getPaginationParams } from '../utility/commonPagination';

export const blogQueryRepository = {
    async getBlogs(query: any): Promise<any> {
        // объявляем входные данные
        const { pageNumber, pageSize, sortBy, sortDirection, searchNameTerm } = getPaginationParams(query);
        //  создаём фильтр для поиска по символам без учёта регистра
        const filter = searchNameTerm ? { name: { $regex: searchNameTerm, $options: 'i' } } : {};
        // получаем общее количество блогов исходя из переданных данных
        const totalCount = await blogCollection.countDocuments(filter);
        // получаем кол-во страниц исходя из полученного кол-ва блогов
        const pagesCount = Math.ceil(totalCount / pageSize);
        // задаём параметры выбранного блога
        const items = await blogCollection.find(filter)
            .sort({ [sortBy]: sortDirection === 'asc' ? 1 : -1 })
            .skip((pageNumber - 1) * pageSize)
            .limit(pageSize)
            .toArray();
        // дополняем данными пагинации видимую модель
        return {
            pagesCount,
            page: pageNumber,
            pageSize,
            totalCount,
            items: items.map(({ _id, ...rest }) => rest) as BlogViewModel[],
        };
    }
};
