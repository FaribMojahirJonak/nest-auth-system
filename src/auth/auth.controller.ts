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
import { AuthGuard } from '@nestjs/passport';
import { refreshTokenCookieOptions } from './constants';
import { Throttle } from '@nestjs/throttler';
import { Logger } from '@nestjs/common';
import { JwtAuthGuard } from './guards/jwt-auth/jwt-auth.guard';
import { ChangePasswordDto } from './dto/change-password.dto';
import { RegisterDto } from './dto/register.dto';
import { RequestPasswordResetDto } from './dto/request-password-reset.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';



@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);
  constructor(private authService: AuthService) { }

  @Post('register')
  @Throttle({ default: { limit: 3, ttl: 60000 * 60 } }) // 3 registrations per hour
  async register(
    @Body() dto: RegisterDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const user = await this.authService.register(
      dto.email,
      dto.password,
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
        // Only log if it's a JWT or auth-related error (expected during logout)
        if (error instanceof ForbiddenException) {
          this.logger.warn('Logout: token already invalid or revoked');
        } else {
          // Re-throw unexpected errors so global exception filter handles them
          throw error;
        }
      }
    }

    res.clearCookie('refreshToken', refreshTokenCookieOptions);

    return { message: 'Logged out successfully' };
  }

  @Post('change-password')
  @UseGuards(JwtAuthGuard)
  async changePassword(
    @Req() req,
    @Body() dto: ChangePasswordDto,
  ) {
    await this.authService.changePassword(
      req.user.userId,
      dto.currentPassword,
      dto.newPassword,
    );

    return { message: 'Password updated successfully' };
  }

  @Post('forgot-password')
  @Throttle({ forgotPassword: { limit: 3, ttl: 60000 * 60 } }) // 3 requests per hour
  async forgotPassword(@Body() dto: RequestPasswordResetDto) {
    await this.authService.requestPasswordReset(dto.email);
    return { message: 'If the email exists, a reset link has been sent' };
  }

  @Post('reset-password')
  @Throttle({ resetPassword: { limit: 5, ttl: 60000 * 60 } }) // 5 attempts per hour
  async resetPassword(@Body() dto: ResetPasswordDto) {
    await this.authService.resetPassword(
      dto.token,
      dto.email,
      dto.newPassword,
    );
    return { message: 'Password reset successfully' };
  }
}
