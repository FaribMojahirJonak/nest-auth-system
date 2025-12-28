import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UserModule } from '../user/user.module';
import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';

@Module({
  imports: [
    UserModule,
    PassportModule,      // 👈 REQUIRED
    JwtModule.register({}),
  ],
  providers: [
    AuthService,
    LocalStrategy,       // 👈 REQUIRED
    JwtStrategy,
  ],
  controllers: [AuthController],
})
export class AuthModule {}
