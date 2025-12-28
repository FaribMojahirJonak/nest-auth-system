import * as Joi from 'joi';

export const envValidationSchema = Joi.object({
  NODE_ENV: Joi.string()
    .valid('development', 'production', 'test')
    .default('development'),

  PORT: Joi.number().default(3000),

  DATABASE_URI: Joi.string()
    .uri()
    .required()
    .messages({
      'any.required': 'DATABASE_URI is required',
      'string.uri': 'DATABASE_URI must be a valid URI',
    }),

  JWT_ACCESS_SECRET: Joi.string()
    .min(32)
    .required()
    .messages({
      'any.required': 'JWT_ACCESS_SECRET is required',
      'string.min': 'JWT_ACCESS_SECRET must be at least 32 characters',
    }),

  JWT_REFRESH_SECRET: Joi.string()
    .min(32)
    .required()
    .messages({
      'any.required': 'JWT_REFRESH_SECRET is required',
      'string.min': 'JWT_REFRESH_SECRET must be at least 32 characters',
    }),

  JWT_ACCESS_EXPIRES_IN: Joi.string()
    .pattern(/^\d+[smhd]$/)
    .required()
    .messages({
      'any.required': 'JWT_ACCESS_EXPIRES_IN is required',
      'string.pattern.base':
        'JWT_ACCESS_EXPIRES_IN must look like 15m, 30s, 1h, 7d',
    }),

  JWT_REFRESH_EXPIRES_IN: Joi.string()
    .pattern(/^\d+[smhd]$/)
    .required()
    .messages({
      'any.required': 'JWT_REFRESH_EXPIRES_IN is required',
      'string.pattern.base':
        'JWT_REFRESH_EXPIRES_IN must look like 7d, 30d',
    }),

  CORS_ORIGIN: Joi.string()
    .uri()
    .default('http://localhost:3000')
    .messages({
      'string.uri': 'CORS_ORIGIN must be a valid URI',
    }),

  FRONTEND_URL: Joi.string()
    .uri()
    .default('http://localhost:3000')
    .messages({
      'string.uri': 'FRONTEND_URL must be a valid URI',
    }),

  MAIL_HOST: Joi.string().optional().default('localhost'),
  MAIL_PORT: Joi.number().optional().default(1025),
  MAIL_USER: Joi.string().optional().default('test'),
  MAIL_PASS: Joi.string().optional().default('test'),
});
