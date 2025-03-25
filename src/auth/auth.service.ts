import { Injectable, BadRequestException, NotFoundException, UnauthorizedException, Inject } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './schemas/user.schema';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { MailerService } from '@nestjs-modules/mailer';
import { ConfigService } from '@nestjs/config';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';

@Injectable()
export class AuthService {
    constructor(
        @InjectModel(User.name) private userModel: Model<User>,
        private jwtService: JwtService,
        private mailerService: MailerService,
        private configService: ConfigService,
        @Inject(CACHE_MANAGER) private cacheManager: Cache,
    ) { }

    async register(registerDto: RegisterDto): Promise<{ message: string }> {
        const { email, password } = registerDto;
        const existingUser = await this.userModel.findOne({ email });
        if (existingUser) {
            throw new BadRequestException('User already exists');
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new this.userModel({ email, password: hashedPassword });
        await newUser.save();

        const token = this.jwtService.sign({ email }, { secret: this.configService.get<string>('JWT_SECRET'), expiresIn: '1d' });
        const verificationUrl = `${this.configService.get<string>('FRONTEND_URL')}/auth/verify-email?token=${token}`;

        await this.mailerService.sendMail({
            to: email,
            subject: 'Verify Your Email',
            html: `<p>Please verify your email by clicking <a href='${verificationUrl}'>here</a>.</p>`
        });

        return { message: 'User registered successfully. Please verify your email.' };
    }

    async verifyEmail(token: string): Promise<{ message: string }> {
        try {
            const { email } = this.jwtService.verify(token, { secret: this.configService.get<string>('JWT_SECRET') });
            const user = await this.userModel.findOne({ email });
            if (!user) {
                throw new NotFoundException('User not found');
            }
            user.isVerified = true;
            await user.save();
            return { message: 'Email verified successfully' };
        } catch (error) {
            throw new BadRequestException('Invalid or expired token');
        }
    }

    async login(loginDto: LoginDto): Promise<{ accessToken: string }> {
        const { email, password } = loginDto;
        const user = await this.userModel.findOne({ email });
        if (!user) {
            throw new UnauthorizedException('Invalid credentials');
        }
        if (!user.isVerified) {
            throw new UnauthorizedException('Email not verified. Please check your email.');
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            throw new UnauthorizedException('Invalid credentials');
        }
        const accessToken = this.jwtService.sign({ email, userId: user._id });
        return { accessToken };
    }

    async logout(token: string): Promise<{ message: string }> {
        const decoded = this.jwtService.decode(token) as { exp: number };
        const expiresIn = decoded.exp - Math.floor(Date.now() / 1000);
        await this.cacheManager.set(`blacklist_${token}`, true, expiresIn );
        return { message: 'Logged out successfully' };
    }

    async isTokenBlacklisted(token: string): Promise<boolean> {
        return !!(await this.cacheManager.get(`blacklist_${token}`));
    }

    async requestPasswordReset(email: string): Promise<{ message: string }> {
        const user = await this.userModel.findOne({ email });
        if (!user) {
          throw new NotFoundException('User not found');
        }
        const resetToken = this.jwtService.sign({ email }, { secret: this.configService.get<string>('JWT_SECRET'), expiresIn: '15m' });
        await this.mailerService.sendMail({
          to: email,
          subject: 'Password Reset Request',
          html: `<p>Click <a href='${this.configService.get<string>('FRONTEND_URL')}/auth/reset-password?token=${resetToken}'>here</a> to reset your password.</p>`
        });
        return { message: 'Password reset link sent' };
      }
    
      async resetPassword(token: string, newPassword: string): Promise<{ message: string }> {
        try {
          const { email } = this.jwtService.verify(token, { secret: this.configService.get<string>('JWT_SECRET') });
          const user = await this.userModel.findOne({ email });
          if (!user) {
            throw new NotFoundException('User not found');
          }
          user.password = await bcrypt.hash(newPassword, 10);
          await user.save();
          return { message: 'Password reset successfully' };
        } catch (error) {
          throw new BadRequestException('Invalid or expired token');
        }
      }
}