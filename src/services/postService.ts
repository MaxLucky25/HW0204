import {postQueryRepository} from "../repositories/postQueryRepository";
import {postRepository} from "../repositories/postRepository";
import {CreatePostDto, UpdatePostDto} from "../models/postModels";


export const postService = {

    async getAllPosts(query: any) {
        return await postQueryRepository.getPosts(query);
    },

    async getPostById(id: string) {
        return await postRepository.getById(id);
    },

    async createPost(input: CreatePostDto) {
        return await postRepository.create(input);
    },

    async updatePost(id:string, input: UpdatePostDto) {
        return await postRepository.update(id, input);
    },

    async deletePost(id:string) {
        return await postRepository.delete(id);
    },
};