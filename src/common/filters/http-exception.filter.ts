import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(HttpExceptionFilter.name);

  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    const status = exception.getStatus();
    const exceptionResponse = exception.getResponse();

    const errorResponse = {
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: request.url,
      message: this.extractMessage(exceptionResponse),
      ...(status === HttpStatus.UNPROCESSABLE_ENTITY && {
        errors: this.extractErrors(exceptionResponse),
      }),
    };

    // Log error for debugging
    this.logger.error(
      `${request.method} ${request.url} - ${status} - ${errorResponse.message}`,
      exception.stack,
    );

    response.status(status).json(errorResponse);
  }

  private extractMessage(response: any): string {
    if (typeof response === 'string') {
      return response;
    }

    if (response && response.message) {
      if (Array.isArray(response.message)) {
        return response.message[0] || 'Bad Request';
      }
      return response.message;
    }

    return 'Internal Server Error';
  }

  private extractErrors(response: any): any {
    if (response && response.message && Array.isArray(response.message)) {
      return response.message;
    }
    return undefined;
  }
}
