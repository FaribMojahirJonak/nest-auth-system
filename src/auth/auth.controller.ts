import {
  Controller,
  Post,
  Body,
  UseGuards,
  Req,
  Res,
  ForbiddenException,
} from '@nestjs/common';
import type { Response, Request } from 'express';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { AuthGuard } from '@nestjs/passport';
import { refreshTokenCookieOptions } from './constants';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) { }

  @Post('register')
async register(
  @Body() dto: RegisterDto,
  @Res({ passthrough: true }) res: Response,
) {
  const user = await this.authService.register(dto.email, dto.password);

  const { accessToken, refreshToken } =
    await this.authService.generateTokens(user);

  await this.authService.updateRefreshToken(user.id, refreshToken);

  res.cookie('refreshToken', refreshToken, refreshTokenCookieOptions);

  return { accessToken };
}


  @Post('refresh')
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
    } catch {
      // swallow error intentionally
    }
  }

  res.clearCookie('refreshToken', refreshTokenCookieOptions);

  return { message: 'Logged out successfully' };
}
}
