import { Injectable, NotFoundException, UseGuards } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './user.entity';

@Injectable()
export class UserService {
    constructor(
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
    ) { }

    async createUser(data: Partial<User>): Promise<User> {
        const user = this.userRepository.create(data);
        return this.userRepository.save(user);
    }

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

    async update(id: string, updatedData: Partial<User>): Promise<User> {
        const user = await this.findById(id);
        if (!user) {
            throw new NotFoundException(`user with id ${id} not found!`);
        }
        const updatedUser = Object.assign(user, updatedData);
        return this.userRepository.save(updatedUser);
    }

    async delete(id: string): Promise<{ message: string }> {
        const result = await this.userRepository.delete(id);
        if (result.affected === 0) {
            throw new NotFoundException(`user with id ${id} not found!`);
        }
        return { message: `user with id ${id} has been deleted successfully.` };
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

    async search(filters: { name?: string; email?: string; age?: number }): Promise<User[]> {
        const queryBuilder = this.userRepository.createQueryBuilder('user');

        if (filters.name) {
            queryBuilder.andWhere('user.name ILIKE :name', { name: `%${filters.name}%` });
        }
        if (filters.email) {
            queryBuilder.andWhere('user.email ILIKE :email', { email: `%${filters.email}%` });
        }
        if (filters.age) {
            queryBuilder.andWhere('user.age = :age', { age: filters.age });
        }
        return queryBuilder.getMany();
    }
}
