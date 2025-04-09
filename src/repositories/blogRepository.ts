import { BlogDBType, CreateBlogDto, UpdateBlogDto, BlogViewModel } from '../models/blogModels';
import {blogCollection} from "../db/mongo-db";

//  функция с правилами и логикой обработки запросов
export const blogRepository = {
    // логика нахождения блога по id
    async getById(id: string): Promise<BlogViewModel | null> {
        const blog = await blogCollection.findOne(
            {id:id},
            {projection: {_id: 0} }
        );
        return blog as BlogViewModel | null;
    },
    // логика создания блога
    async create(input: CreateBlogDto): Promise<BlogViewModel> {
        const newBlog: BlogDBType = {
            id: Date.now().toString(),
            ...input,
            createdAt: new Date(),
            isMembership: false,
        };
        // создание блога
        const result = await blogCollection.insertOne(newBlog);
        // нахождение добавленого блога
        const created = await blogCollection.findOne({ _id: result.insertedId });
        // возвращение созданного блога без objectId
        return this.mapToOutput(created!);

    },
    // обновление блога по id
    async update(id: string, input: UpdateBlogDto): Promise<boolean> {
       const result = await blogCollection.updateOne(
           // id блога который мы хотим обновить
           {id:id},
           // параметрый которые мы можем изменить
           { $set: {
                   name: input.name,
                   description: input.description,
                   websiteUrl: input.websiteUrl
               }}
       );
       // проверка обновления
       return result.matchedCount === 1;
    },
    // логика удаления блога по id
    async delete(id: string): Promise<boolean> {
        const result = await blogCollection.deleteOne({id:id});
        return result.deletedCount === 1;
    },
    // функция которая возвращает блог без _id
    mapToOutput(blog: BlogDBType): BlogViewModel {
        const { _id, ...rest } = blog;
        return rest;
    }
};