import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

import * as cookieParser from 'cookie-parser';
import { ValidationContext } from 'graphql';
import { BadRequestException, ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

 
  app.enableCors({ // cross origin resources sharing // for conncting backend and frontend
    origin: 'http://127.0.0.1:5174',
    credentials: true,
    // all headers that client are allowed to use
    allowedHeaders: [
      'Accept',
      'Authorization',
      'Content-Type',
      'X-Requested-With',
      'apollo-require-preflight',
    ],
    methods: ['GET', 'PUT', 'POST', 'DELETE', 'OPTIONS'],
  });

  app.use(cookieParser());

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // filter out properties that not required for validation
      // forbidNonWhitelisted: true,
      transform: true, // tranform object as per the DTO classes

      exceptionFactory: (errors) => {
        const formattedErrors = errors.reduce((accumulator, error) => {
          accumulator[error.property] = Object.values(error.constraints).join(
            ', ',
          );
          return accumulator;
        }, {});
        console.log('formattedErrors123', formattedErrors);
        // return formatted errors being an object with properties mapping to errors
        throw new BadRequestException(formattedErrors);
      },
    

    })
  );
  await app.listen(3001);
}
bootstrap();
