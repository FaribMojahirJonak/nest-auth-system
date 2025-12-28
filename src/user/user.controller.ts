import { Body, Controller, Delete, Get, Param, Post, Put, Query, Req, UseGuards } from '@nestjs/common';
import { UserService } from './user.service';
import { User } from './user.entity';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth/jwt-auth.guard';
import { Roles } from 'src/auth/decorators/roles/roles.decorator';
import { RolesGuard } from 'src/auth/guards/roles/roles.guard';


@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('user')
export class UserController {
    constructor(
        private readonly userService: UserService,
    ) {}

    @Get()
    @Roles('admin')
    async findAll(): Promise<User[]> {
        return this.userService.findAll();
    }

    @Get('profile')
    async getProfile(@Req() req) {
        return req.user;
    }
}
