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
});
