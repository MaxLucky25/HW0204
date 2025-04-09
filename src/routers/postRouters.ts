import { Router, Request, Response } from 'express';
import { postValidators } from '../validators/postValidators';
import { authMiddleware } from '../middlewares/authMiddleware';
import { inputCheckErrorsMiddleware } from '../middlewares/validationMiddleware';
import {postService} from "../services/postService";
import {commentService} from "../services/commentService";
import {jwtAuthMiddleware} from "../middlewares/jwtAuthMiddleware";
import {commentValidators} from "../validators/commentValidators";

export const postsRouter = Router();

postsRouter.get('/', async (req: Request, res: Response) => {
    const result = await postService.getAllPosts(req.query);
    res.status(200).json(result);
});

postsRouter.get('/:id', async (req: Request, res: Response) => {
    const post = await postService.getPostById(req.params.id);
    post ? res.json(post) : res.sendStatus(404);
});

postsRouter.post('/',
    authMiddleware,
    ...postValidators,
    inputCheckErrorsMiddleware,
    async (req: Request, res: Response) => {
        const newPost = await postService.createPost(req.body);
        newPost ? res.status(201).json(newPost) : res.sendStatus(400);
    }
);

postsRouter.put('/:id',
    authMiddleware,
    ...postValidators,
    inputCheckErrorsMiddleware,
    async (req: Request, res: Response) => {
        const updated = await postService.updatePost(req.params.id, req.body);
        updated ? res.sendStatus(204) : res.sendStatus(404);
    }
);

postsRouter.delete('/:id',
    authMiddleware,
    async (req: Request, res: Response) => {
        const deleted = await postService.deletePost(req.params.id);
        deleted ? res.sendStatus(204) : res.sendStatus(404);
    }
);


// возвращает комментарии для указанного поста
postsRouter.get('/:postId/comments', async (req: Request, res: Response) => {
    const { postId } = req.params;
    const comments = await commentService.getCommentsByPostId(postId, req.query);
    if (comments === null) {
        res.sendStatus(404);
    } else {
        res.status(200).json(comments);
    }
});

//  создание нового комментария (Bearer auth)
postsRouter.post('/:postId/comments',
    jwtAuthMiddleware,
    commentValidators,
    inputCheckErrorsMiddleware,
    async (req: Request, res: Response) => {
        const { postId } = req.params;
        const commentatorInfo = {
            userId: req.userId!,
            userLogin: req.userLogin!
        };
        const newComment = await commentService.createComment(postId, { content: req.body.content }, commentatorInfo);
        if (newComment) {
            res.status(201).json(newComment);
        } else {
            res.sendStatus(404); // если пост не найден
        }
    }
);