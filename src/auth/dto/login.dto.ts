import { IsEmail, IsString, MaxLength, MinLength } from 'class-validator';

export class LoginDto {
  @IsEmail({}, { message: 'Invalid email format' })
  @MaxLength(255, { message: 'Email must be at most 255 characters' })
  email: string;

  @IsString({ message: 'Password must be a string' })
  @MinLength(1, { message: 'Password must not be empty' })
  @MaxLength(1000, { message: 'Password must be at most 1000 characters' })
  password: string;
}
