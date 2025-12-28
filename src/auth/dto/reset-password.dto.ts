import { IsString, Matches, IsEmail, MinLength, MaxLength } from 'class-validator';
import { Transform } from 'class-transformer';

export class ResetPasswordDto {
  @IsEmail()
  @Transform(({ value }) => value.trim().toLowerCase())
  email: string;

  @IsString()
  @MinLength(32)
  @MaxLength(256)
  token: string;

  @IsString()
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/,
    {
      message:
        'Password must be at least 12 characters long and include uppercase, lowercase, number, and special character',
    },
  )
  newPassword: string;
}
