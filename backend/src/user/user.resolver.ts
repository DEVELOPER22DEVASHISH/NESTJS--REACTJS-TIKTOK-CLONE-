import { Args, Context, Mutation, Query, Resolver } from '@nestjs/graphql';
import { AuthService } from 'src/auth/auth.service';
import { BadRequestException, UseFilters, UseGuards } from '@nestjs/common';
import { UserService } from './user.service';
import { LoginResponse, RegisterResponse } from 'src/auth/types';
import { LoginDto, RegisterDto } from 'src/auth/dto';
import { Response, Request } from 'express';
import { GraphqlAuthGuard } from 'src/auth/graphql-auth/graphql-auth.gaurd';
import { User } from './user.model';
import { GraphQLRequestContextWillSendSubsequentPayload } from '@apollo/server/dist/esm/externalTypes/requestPipeline';
import { join } from 'path';
import { createWriteStream } from 'fs';
import { v4 as uuidv4 } from 'uuid';

@Resolver()
export class UserResolver { // as controller in rest api


    constructor(
        private readonly authService:AuthService,
        private readonly userService:UserService,
    ) { }

    @Mutation(() => RegisterResponse)
    async register(
        @Args('registerInput') registerDto: RegisterDto,
        @Context() context: {res: Response},

    ): Promise<RegisterResponse> {

        if (registerDto.password !== registerDto.confirmPassword) {
            throw new BadRequestException({
              confirmPassword: 'Password and confirm password are not the same.',
            });

        }

        try {
            const { user } = await this.authService.register(
              registerDto,
              context.res, // error  fixing by  creating types.d.td file and importing response from express
            );
            console.log('user!', user);
            return { user };
          } catch (error) {
            // Handle the error, for instance if it's a validation error or some other type
            return {
              error: {
                message: error.message,
                // code: 'SOME_ERROR_CODE' // If you have error codes
              },
            };
          }
    
    }

    @Mutation(() => LoginResponse) // Adjust this return type as needed
    async login(
      @Args('loginInput') loginDto: LoginDto, // accessing login dto
      @Context() context: { res: Response },
    ) {
      return this.authService.login(loginDto, context.res);
    }

    @Mutation(() => String)
    async logout(@Context() context: { res: Response }) {
      return this.authService.logout(context.res);
    }
  
    @UseGuards(GraphqlAuthGuard)
    @Query(() => String)
    getProtectedData() {
      return 'This is protected data';
    }
  
    @Mutation(() => String)
    async refreshToken(@Context() context: { req: Request; res: Response }) {
      try {
        return this.authService.refreshToken(context.req, context.res);
      } catch (error) {
        throw new BadRequestException(error.message);
      }
    }

    @Query(() => String)
    async hello() {
        return 'Hello world'
    }
   
} 
