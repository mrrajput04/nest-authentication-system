import { Controller, Post, Body, Get, Query, Headers, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    @Post('register')
    async register(@Body() registerDto: RegisterDto) {
        return this.authService.register(registerDto);
    }

    @Get('verify-email')
    async verifyEmail(@Query('token') token: string) {
        return this.authService.verifyEmail(token);
    }

    @Post('login')
    async login(@Body() loginDto: LoginDto) {
        return this.authService.login(loginDto);
    }

    @Post('logout')
    async logout(@Headers('Authorization') authHeader: string) {
        if (!authHeader) {
            throw new UnauthorizedException('No token provided');
        }
        const token = authHeader.replace('Bearer ', '');
        return this.authService.logout(token);
    }

    @Post('request-password-reset')
    async requestPasswordReset(@Body('email') email: string) {
      return this.authService.requestPasswordReset(email);
    }
  
    @Post('reset-password')
    async resetPassword(@Query('token') token: string, @Body('newPassword') newPassword: string) {
      return this.authService.resetPassword(token, newPassword);
    }

}
