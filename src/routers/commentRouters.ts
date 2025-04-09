import { Router, Request, Response } from 'express';
import { jwtAuthMiddleware } from '../middlewares/jwtAuthMiddleware';
import { inputCheckErrorsMiddleware } from '../middlewares/validationMiddleware';
import { commentService } from '../services/commentService';
import { commentValidators } from '../validators/commentValidators';


export const commentRouter = Router();

// Обновление комментария
commentRouter.put('/:commentId',
    jwtAuthMiddleware,
    commentValidators,
    inputCheckErrorsMiddleware,
    async (req: Request, res: Response) => {
        const { commentId } = req.params;
        const userId = req.userId!;
        const comment = await commentService.getCommentById(commentId);
        if (!comment) {
            res.sendStatus(404);
            return;
        }
        if (comment.commentatorInfo.userId !== userId) {
            res.sendStatus(403);
            return;
        }
        const updated = await commentService.updateComment(commentId, { content: req.body.content });
        updated ? res.sendStatus(204) : res.sendStatus(400);
    }
);
// Удаление комментария
commentRouter.delete('/:commentId',
    jwtAuthMiddleware,
    async (req: Request, res: Response) => {
        const { commentId } = req.params;
        const userId = req.userId!;
        const comment = await commentService.getCommentById(commentId);
        if (!comment) {
            res.sendStatus(404);
            return;
        }
        if (comment.commentatorInfo.userId !== userId) {
            res.sendStatus(403);
            return;
        }
        const deleted = await commentService.deleteComment(commentId);
        deleted ? res.sendStatus(204) : res.sendStatus(404);
    }
);

// Получение комментария по id
commentRouter.get('/:id', async (req: Request, res: Response) => {
    const { id } = req.params;
    const comment = await commentService.getCommentById(id);
    if (comment) {
        res.status(200).json(comment);
    } else {
        res.sendStatus(404);
    }
});
