import { IsEmail, IsOptional, IsString, Matches, MaxLength, MinLength } from 'class-validator';

export class RegisterDto {
  @IsEmail({}, { message: 'Invalid email format' })
  @MaxLength(255, { message: 'Email must be at most 255 characters' })
  email: string;

  @IsString({ message: 'Password must be a string' })
  @MinLength(1, { message: 'Password must not be empty' })
  @MaxLength(1000, { message: 'Password must be at most 1000 characters' })
  password: string;

  @IsOptional()
  @IsString({ message: 'Username must be a string' })
  @MinLength(1, { message: 'Username must not be empty' })
  @MaxLength(50, { message: 'Username must be at most 50 characters' })
  @Matches(/^[a-zA-Z0-9_-]+$/, {
    message: 'Username may only contain letters, digits, underscores and hyphens',
  })
  username?: string;
}
