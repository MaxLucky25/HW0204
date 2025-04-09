
// добавили новые значения и свойства в глобальную области видимости
declare global {
    namespace Express {
        export interface Request {
            userId: string | null;
            userLogin?: string;
            userEmail?: string;
        }
    }
}
export {};