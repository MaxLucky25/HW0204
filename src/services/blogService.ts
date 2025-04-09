import {blogQueryRepository} from "../repositories/blogQueryRepository";
import {blogRepository} from "../repositories/blogRepository";
import {CreateBlogDto, UpdateBlogDto} from "../models/blogModels";
import {postQueryRepository} from "../repositories/postQueryRepository";
import {CreatePostDto} from "../models/postModels";
import {postRepository} from "../repositories/postRepository";


export const blogService = {
    async getAllBlogs(query: any) {
        return await blogQueryRepository.getBlogs(query);
    },

    async getBlogBYId(id: string) {
        return await blogRepository.getById(id);
    },

    async createBlog(input: CreateBlogDto){
        return await blogRepository.create(input);
    },

    async updateBlog(id: string, input: UpdateBlogDto){
        return await blogRepository.update(id, input);
    },

    async deleteBlog(id: string){
        return await blogRepository.delete(id);
    },

    async getPostsForBlog(blogId: string, query: any){
        return await postQueryRepository.getPostsByBlogId(blogId,query);
    },

    async createPostsForBlog(blogId: string, input: Omit<CreatePostDto, 'blogId'>){
        const postInput: CreatePostDto = {...input,blogId};
        return await postRepository.create(postInput);
    },
};