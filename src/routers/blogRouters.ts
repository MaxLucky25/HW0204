
import { Router } from 'express';
import {blogValidators} from '../validators/blogValidators';
import { authMiddleware } from '../middlewares/authMiddleware';
import { inputCheckErrorsMiddleware } from '../middlewares/validationMiddleware';
import {postForSpecificBlogValidators} from "../validators/postForSpecificBlogValidators";
import {blogService} from "../services/blogService";

export const blogsRouter = Router();

blogsRouter.get('/', async (req, res) => {
    const result = await blogService.getAllBlogs(req.query);
    res.status(200).json(result);
});

blogsRouter.get('/:id', async (req, res) => {
    const blog = await blogService.getBlogBYId(req.params.id);
    blog ? res.json(blog) : res.sendStatus(404);
});

blogsRouter.post('/',
    authMiddleware,
    ...blogValidators,
    inputCheckErrorsMiddleware,
    async (req, res) => {
        const newBlog = await blogService.createBlog(req.body);
        res.status(201).json(newBlog);
    }
);

blogsRouter.put('/:id',
    authMiddleware,
    ...blogValidators,
    inputCheckErrorsMiddleware,
    async (req, res) => {
        const updated = await blogService.updateBlog(req.params.id, req.body);
        updated ? res.sendStatus(204) : res.sendStatus(404);
    }
);

blogsRouter.delete('/:id',
    authMiddleware,
    async (req, res) => {
        const deleted = await blogService.deleteBlog(req.params.id);
        deleted ? res.sendStatus(204) : res.sendStatus(404);
    }
);

blogsRouter.get('/:id/posts', async (req, res) => {
    const blog = await blogService.getBlogBYId(req.params.id);
    if (!blog) {
        res.sendStatus(404);
        return;
    }
    const result = await blogService.getPostsForBlog(req.params.id, req.query);
    res.status(200).json(result);
});


blogsRouter.post('/:id/posts',
    authMiddleware,
    ...postForSpecificBlogValidators,
    inputCheckErrorsMiddleware,
    async (req, res) => {
        const blog = await blogService.getBlogBYId(req.params.id);
        if (!blog) {
            res.sendStatus(404);
            return;
        }
        const newPost = await blogService.createPostsForBlog(req.params.id, req.body);
        newPost ? res.status(201).json(newPost) : res.sendStatus(400);
    }
);