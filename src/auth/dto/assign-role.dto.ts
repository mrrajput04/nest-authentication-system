import { IsNotEmpty, IsString } from 'class-validator';

export class AssignRoleDto {
  @IsNotEmpty()
  @IsString()
  role: string;
}
