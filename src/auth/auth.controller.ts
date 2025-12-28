import {
  Controller,
  Post,
  Body,
  UseGuards,
  Req,
  Res,
  ForbiddenException,
  Get,
} from '@nestjs/common';
import type { Response, Request } from 'express';
import { AuthService } from './auth.service';
import { AuthGuard } from '@nestjs/passport';
import { refreshTokenCookieOptions } from './constants';
import { Throttle, ThrottlerGuard } from '@nestjs/throttler';
import { Logger } from '@nestjs/common';



@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);
  constructor(private authService: AuthService) { }

  @Post('register')
  @Throttle({ default: { limit: 3, ttl: 60000 * 60 } }) // 3 registrations per hour
  async register(
    @Req() req,
    @Res({ passthrough: true }) res: Response,
  ) {
    const user = await this.authService.register(
      req.body.email,
      req.body.password,
    );

    const { accessToken, refreshToken } =
      await this.authService.generateTokens(user);

    await this.authService.updateRefreshToken(user.id, refreshToken);

    res.cookie('refreshToken', refreshToken, refreshTokenCookieOptions);

    return { accessToken };
  }



  @Post('refresh')
  @Throttle({ refresh: {} })
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const refreshToken = req.cookies['refreshToken'];

    if (!refreshToken) {
      throw new ForbiddenException('No refresh token');
    }

    const { accessToken, refreshToken: newRefreshToken } =
      await this.authService.refreshTokens(refreshToken);

    res.cookie('refreshToken', newRefreshToken, refreshTokenCookieOptions);

    return { accessToken };
  }

  @Post('login')
  @Throttle({ login: {} })
  @UseGuards(AuthGuard('local'))
  async login(@Req() req, @Res({ passthrough: true }) res: Response) {
    const user = req.user;

    const { accessToken, refreshToken } =
      await this.authService.generateTokens(user);

    await this.authService.updateRefreshToken(user.id, refreshToken);

    res.cookie('refreshToken', refreshToken, refreshTokenCookieOptions);

    return { accessToken };
  }


  @Post('logout')
  async logout(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const refreshToken = req.cookies['refreshToken'];

    if (refreshToken) {
      try {
        await this.authService.invalidateRefreshToken(refreshToken);
      } catch (error) {
        this.logger.warn('Logout token invalid or already revoked');
      }
    }

    res.clearCookie('refreshToken', refreshTokenCookieOptions);

    return { message: 'Logged out successfully' };
  }
}
