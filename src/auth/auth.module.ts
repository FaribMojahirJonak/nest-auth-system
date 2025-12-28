import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UserModule } from '../user/user.module';
import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';
import { MailModule } from '../mail/mail.module';

@Module({
  imports: [
    UserModule,
    PassportModule,      // 👈 REQUIRED
    JwtModule.register({}),
    MailModule,          // 👈 For email sending
  ],
  providers: [
    AuthService,
    LocalStrategy,       // 👈 REQUIRED
    JwtStrategy,
  ],
  controllers: [AuthController],
})
export class AuthModule {}
