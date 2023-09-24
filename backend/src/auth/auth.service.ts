import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

import { PrismaService } from '../prisma.service'; 
import { Response, Request } from 'express';

import * as bcrypt from 'bcrypt';
import { User } from '@prisma/client';

import { ConfigService } from '@nestjs/config';
import { access } from 'fs';
import { LoginDto, RegisterDto } from './dto';
@Injectable()
export class AuthService {
    constructor(
        private readonly jwtService: JwtService,
        private readonly prisma: PrismaService,
        private readonly configService: ConfigService,
    ){}

    async refreshToken(req: Request, res: Response): Promise<string>{
        const refreshToken = req.cookies['refresh_token'];

        if (!refreshToken) {
            throw new UnauthorizedException('Refresh token not available');
        }

        let payload;
        try {
            payload = this.jwtService.verify(refreshToken, {
                secret: this.configService.get<string>('REFRESH TOKEN SECRET'),
            })
        } catch (error) {
            throw new UnauthorizedException('Invalid refresh token or it has expired')
        }

        const userExists = await this.prisma.user.findUnique({ // looking unique user by id
            where: {id: payload.sub},
        });

        if (!userExists) {
            throw new BadRequestException('User no longer exist')
        }

        const expiresIn = 15000; // access token expiration
        const expiration = Math.floor(Date.now()/ 1000) + expiresIn;
        const accessToken = this.jwtService.sign(
            {...payload, exp: expiration},
            {
                secret: this.configService.get<string>('ACCESS_TOKEN_SECRET'),
            },
        );
        res.cookie('access_token', accessToken, {httpOnly: true}); // true means it is secure and it can not accessed by javascript browsers

        return accessToken;

       
    } 

    private async issueToken(user:User, response:Response){ // private message
        const payload = {username: user.fullname, sub: user.id}

        const accessToken = this.jwtService.sign(
            {...payload},
            {
                secret: this.configService.get<string>('ACCESS_TOKEN_SECRET'),
                expiresIn: '150sec'
            },
        )
        
        const refreshToken = this.jwtService.sign(payload,{
            secret: this.configService.get<string>('REFRESH_TOKEN_SECRET'),
            expiresIn: '7d'
        });

        response.cookie('access_token', accessToken ,{httpOnly: true});
        response.cookie('refresh_token', refreshToken ,{httpOnly: true});

        return { user};

    }

    async validateUser(loginDto: LoginDto){
        const user = await this.prisma.user.findUnique({ // email is unique
            where: {email: loginDto.email, }
        });

        if (user && ( await bcrypt.compare(loginDto.password, user.password))){
            return user;
        }
        return null;
    }

    async register(registerDto:RegisterDto, response:Response){

        const existingUser = await this.prisma.user.findUnique({
            where: { email: registerDto.email},
        });

        if (existingUser) {
            throw new Error('Email already in use');
        }
        const hashedPassword = await bcrypt.hash(registerDto.password, 10) // sort value of 10 

        const user =  await this.prisma.user.create({ // creating a new user
            data: {
                fullname: registerDto.fullname,
                password: hashedPassword,
                email: registerDto.email,
            },
        });

        return this.issueToken(user, response); // once user has created token being issue 
    }

    async login(loginDto: LoginDto, response: Response){
        const user = await this.validateUser(loginDto);

        if(!user) {
            throw new UnauthorizedException('Inavalid credentials');
        }
        return this.issueToken(user, response);
    }

    async logout(response: Response) {
        response.clearCookie('access_token');
        response.clearCookie('refresh_token');
        return 'SuccessFully logged out'
    }
}
