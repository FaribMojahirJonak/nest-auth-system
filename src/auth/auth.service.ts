import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import type { StringValue } from 'ms';
import { MailService } from 'src/mail/mail.service';
import { User } from '../user/user.entity';
import { UserService } from '../user/user.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly mailService: MailService,
  ) {}

  async validateUser(email: string, password: string): Promise<User | null> {
    const user = await this.userService.findByEmail(email);
    if (!user) return null;

    const passwordValid = await bcrypt.compare(password, user.password);
    if (!passwordValid) return null;

    return user;
  }

  async register(email: string, password: string) {
    const existingUser = await this.userService.findByEmail(email);

    if (existingUser) {
      throw new ConflictException('Email already registered');
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    return this.userService.create({
      email,
      password: hashedPassword,
    });
  }


  private getExpiresIn(key: string, fallback: StringValue): StringValue {
    return (this.configService.get<string>(key) ?? fallback) as StringValue;
  }

  async generateTokens(user: User) {
    const payload = {
      sub: user.id,
      email: user.email,
      role: user.role,
    };

    const accessToken = await this.jwtService.signAsync(payload, {
      secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
      expiresIn: this.getExpiresIn('JWT_ACCESS_EXPIRES_IN', '15m'),
    });

    const refreshToken = await this.jwtService.signAsync(payload, {
      secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      expiresIn: this.getExpiresIn('JWT_REFRESH_EXPIRES_IN', '7d'),
    });

    return { accessToken, refreshToken };
  }

  // 🔐 Store hashed refresh token
  async updateRefreshToken(userId: string, refreshToken: string) {
    const hashed = await bcrypt.hash(refreshToken, 12);
    await this.userService.update(userId, {
      hashedRefreshToken: hashed,
    });
  }

  // 🔁 REFRESH FLOW (THIS IS THE KEY METHOD)
  async refreshTokens(refreshToken: string) {
    let payload: any;

    // 1️⃣ Verify refresh token signature
    try {
      payload = await this.jwtService.verifyAsync(refreshToken, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      });
    } catch {
      throw new ForbiddenException('Invalid refresh token');
    }

    // 2️⃣ Find user
    const user = await this.userService.findById(payload.sub);
    if (!user || !user.hashedRefreshToken) {
      throw new ForbiddenException('Access denied');
    }

    // 3️⃣ Compare token hash
    const isValid = await bcrypt.compare(
      refreshToken,
      user.hashedRefreshToken,
    );

    if (!isValid) {
      throw new ForbiddenException('Access denied');
    }

    // 4️⃣ Rotate tokens
    const tokens = await this.generateTokens(user);
    await this.updateRefreshToken(user.id, tokens.refreshToken);

    return tokens;
  }

  async invalidateRefreshToken(refreshToken: string) {
    const payload = await this.jwtService.verifyAsync(refreshToken, {
      secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
    });

    await this.userService.update(payload.sub, {
      hashedRefreshToken: null,
    });
  }

  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
  ) {
    const user = await this.userService.findById(userId);

    const passwordMatches = await bcrypt.compare(
      currentPassword,
      user.password,
    );

    if (!passwordMatches) {
      throw new ForbiddenException('Invalid credentials');
    }

    const newHashedPassword = await bcrypt.hash(newPassword, 12);

    await this.userService.update(userId, {
      password: newHashedPassword,
      hashedRefreshToken: null, // invalidate all sessions
    });
  }

  async requestPasswordReset(email: string) {
    const user = await this.userService.findByEmail(email);

    if (!user) {
      return; // prevent user enumeration
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenHash = await bcrypt.hash(resetToken, 12);

    await this.userService.update(user.id, {
      passwordResetTokenHash: resetTokenHash,
      passwordResetTokenExpiresAt: new Date(Date.now() + 15 * 60 * 1000),
    });

    const frontendUrl = this.configService.get<string>('FRONTEND_URL') ?? '';
    const resetLink = `${frontendUrl}/reset-password?token=${resetToken}&email=${encodeURIComponent(user.email)}`;

    await this.mailService.sendPasswordReset(user.email, resetLink);
  }

  async resetPassword(
    token: string,
    email: string,
    newPassword: string,
  ) {
    const user = await this.userService.findByEmail(email);

    if (
      !user ||
      !user.passwordResetTokenHash ||
      !user.passwordResetTokenExpiresAt
    ) {
      throw new BadRequestException('Invalid or expired reset token');
    }

    if (new Date() > user.passwordResetTokenExpiresAt) {
      throw new BadRequestException(
        'Reset token has expired. Please request a new one.',
      );
    }

    const tokenValid = await bcrypt.compare(
      token,
      user.passwordResetTokenHash,
    );

    if (!tokenValid) {
      throw new BadRequestException('Invalid or expired reset token');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);

    await this.userService.update(user.id, {
      password: hashedPassword,
      hashedRefreshToken: null, // invalidate all sessions
      passwordResetTokenHash: null,
      passwordResetTokenExpiresAt: null,
    });
  }


}
