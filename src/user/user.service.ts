import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './user.entity';

@Injectable()
export class UserService {
    constructor(
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
    ) { }

    async findAll(): Promise<User[]> {
        return this.userRepository.find();
    }

    async findById(id: string): Promise<User> {
        const user = await this.userRepository.findOneBy({ id });
        if (!user) {
            throw new NotFoundException(`user with id ${id} not found!`);
        }
        return user;
    }

    async findByEmail(email: string): Promise<User | null> {
        return this.userRepository.findOne({
            where: { email },
        });
    }

    async create(data: Partial<User>): Promise<User> {
        const user = this.userRepository.create(data);
        return this.userRepository.save(user);
    }

    async update(id: string, updatedData: Partial<User>): Promise<User> {
        const user = await this.findById(id);
        if (!user) {
            throw new NotFoundException(`user with id ${id} not found!`);
        }
        const updatedUser = Object.assign(user, updatedData);
        return this.userRepository.save(updatedUser);
    }
}
