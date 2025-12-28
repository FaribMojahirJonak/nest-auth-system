import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { AuthModule } from './auth/auth.module';
import { User } from './user/user.entity';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),

    TypeOrmModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        type: 'postgres',
        url: config.get<string>('DATABASE_URI'),
        entities: [User],
        synchronize: true, // ⚠️ dev only
      }),
    }),

    ThrottlerModule.forRoot({
      throttlers: [
    {
      name: 'default',
      ttl: 60000, // 60 seconds in milliseconds
      limit: 10,
    },
    {
      name: 'login',
      ttl: 60000 * 15, // 15 minutes in milliseconds
      limit: 5,
    },
    {
      name: 'refresh',
      ttl: 60000 * 15, // 15 minutes in milliseconds
      limit: 10,
    },
  ],
    }),

    AuthModule,
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AppModule {}
