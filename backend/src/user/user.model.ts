import {Field, ObjectType} from '@nestjs/graphql'

@ObjectType()
export class User { // user is graphql object type
  @Field() // marks as properties
  id?: number;

  @Field()
  fullname: string;

  @Field()
  email?: string;
  @Field({ nullable: true })
  bio?: string;

  @Field({ nullable: true })
  image: string;

  @Field()
  password: string;

  @Field()
  createdAt: Date;

  @Field()
  updatedAt: Date;
}