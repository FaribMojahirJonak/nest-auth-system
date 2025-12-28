import { Body, Controller, Delete, Get, Param, Post, Put, Query, Req, UseGuards } from '@nestjs/common';
import { UserService } from './user.service';
import { User } from './user.entity';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth/jwt-auth.guard';
import { Roles } from 'src/auth/decorators/roles/roles.decorator';
import { RolesGuard } from 'src/auth/guards/roles/roles.guard';


@UseGuards(JwtAuthGuard)
@Controller('user')
export class UserController {
    constructor(
        private readonly userService: UserService,
    ) { }

    @Post()
    async createUser(@Body() data: Partial<User>): Promise<User> {
        return this.userService.createUser(data);
    }

    @Get()
    @Roles('admin')
    @UseGuards(JwtAuthGuard, RolesGuard)
    async findAll(): Promise<User[]> {
        return this.userService.findAll();
    }

    @Get('me')
    async getMe(@Req() req) {
        return req.user;
    }

    @Get('search')
    async searchUsers(@Query('name') name?: string, @Query('email') email?: string, @Query('age') age?: number): Promise<User[]> {
        return this.userService.search({ name, email, age });
    }

    @Get(':id')
    async findOne(@Param('id') id: string): Promise<User> {
        return this.userService.findById(id);
    }

    @Put(':id')
    async updateUser(@Param('id') id: string, @Body() updatedData: Partial<User>): Promise<User> {
        return this.userService.update(id, updatedData);
    }

    @Delete(':id')
    async deleteUser(@Param('id') id: string): Promise<{ message: string }> {
        return this.userService.delete(id);
    }

    
}
