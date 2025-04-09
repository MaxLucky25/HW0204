

const config = {
    JWT_SECRET: process.env.JWT_SECRET || "default_secret",
    JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || "10s",
    JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET || "default_secret",
    JWT_REFRESH_EXPIRES_IN: process.env.JWT_REFRESH_EXPIRES_IN || "20s",
    EMAIL_USER: process.env.EMAIL_USER || "your-email@gmail.com",
    EMAIL_PASS: process.env.EMAIL_PASS || "your-password",
};

export default config;