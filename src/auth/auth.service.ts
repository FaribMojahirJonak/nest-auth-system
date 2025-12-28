import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { UserService } from '../user/user.service';
import { User } from '../user/user.entity';
import { StringValue } from 'ms';
import { ForbiddenException } from '@nestjs/common';


@Injectable()
export class AuthService {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
  ) { }

  async validateUser(email: string, password: string): Promise<User | null> {
    const user = await this.userService.findByEmail(email);
    if (!user) return null;

    const passwordValid = await bcrypt.compare(password, user.password);
    if (!passwordValid) return null;

    return user;
  }

  async register(email: string, password: string): Promise<User> {
    const hashedPassword = await bcrypt.hash(password, 10);
    return this.userService.create({
      email,
      password: hashedPassword,
    });
  }

  async generateTokens(user: User) {
    const payload = {
      sub: user.id,
      email: user.email,
      role: user.role,
    };

    const accessToken = await this.jwtService.signAsync(payload, {
      secret: process.env.JWT_ACCESS_SECRET as string,
      expiresIn: process.env.JWT_ACCESS_EXPIRES_IN as StringValue,
    });

    const refreshToken = await this.jwtService.signAsync(payload, {
      secret: process.env.JWT_REFRESH_SECRET as string,
      expiresIn: process.env.JWT_REFRESH_EXPIRES_IN as StringValue,
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
        secret: process.env.JWT_REFRESH_SECRET as string,
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
    secret: process.env.JWT_REFRESH_SECRET as string,
  });

  await this.userService.update(payload.sub, {
    hashedRefreshToken: null,
  });
}

}
