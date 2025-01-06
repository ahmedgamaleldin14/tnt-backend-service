import {
  BadRequestException,
  Body,
  Controller,
  HttpException,
  InternalServerErrorException,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { LoginUserDto } from '../dto/login-user.dto';
import { AuthService } from '../services/auth.service';
import { JwtRefreshAuthGuard } from '../guards/jwt-refresh.guard';
import { CreateUserDto } from '../dto/create-user.dto';
import { REFRESH_TOKEN_COOKIE_NAME } from '../constants/auth.constants';
import {
  ApiBadRequestResponse,
  ApiOperation,
  ApiResponse,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @ApiOperation({ summary: 'Logs in a user and sets the auth cookies' })
  @ApiResponse({ status: 200, description: 'Successfully logged in' })
  @ApiBadRequestResponse({ description: 'Invalid credentials' })
  @Post('login')
  async login(@Body() request: LoginUserDto, @Res({ passthrough: true }) res) {
    try {
      const user = await this.authService.validateUser(
        request.email,
        request.password,
      );
      if (user) {
        const tokens = await this.authService.generateTokens(user);

        this.authService.setAuthCookies(res, tokens);

        return user;
      }

      throw new UnauthorizedException({
        error_code: 'invalid_credentials',
        message: 'Invalid credentials',
      });
    } catch (e) {
      if (!(e instanceof HttpException))
        throw new InternalServerErrorException({
          error_code: 'internal_server_error',
          message: 'Internal server error',
        });
      throw e;
    }
  }

  @ApiOperation({ summary: 'Refreshes the access token' })
  @ApiResponse({ status: 200, description: 'Successfully refreshed' })
  @ApiUnauthorizedResponse({ description: 'Invalid refresh token' })
  @Post('refresh')
  @UseGuards(JwtRefreshAuthGuard)
  async refresh(@Req() req, @Res({ passthrough: true }) res) {
    try {
      const refreshToken = req.cookies[REFRESH_TOKEN_COOKIE_NAME];
      const tokens = await this.authService.refreshTokens(refreshToken, false);
      this.authService.setAuthCookies(res, tokens);
    } catch (e) {
      if (!(e instanceof HttpException))
        throw new InternalServerErrorException({
          error_code: 'internal_server_error',
          message: 'Internal server error',
        });
      throw e;
    }
  }

  @ApiOperation({ summary: 'Registers a new user' })
  @ApiResponse({ status: 200, description: 'Successfully registered' })
  @ApiBadRequestResponse({ description: 'Email already in use' })
  @Post('register')
  async register(@Body() request: CreateUserDto) {
    try {
      const name = request.name;
      const email = request.email;
      const password = request.password;
      const existingUser = await this.authService.userExistsByEmail(email);
      if (existingUser) {
        throw new BadRequestException({
          error_code: 'email_in_use',
          message: 'Email already in use',
        });
      }

      const user = await this.authService.createUser(name, email, password);
      if (user) {
        return user;
      }
      throw new InternalServerErrorException({
        error_code: 'user_creation_failed',
        message: 'Failed to create user',
      });
    } catch (e) {
      if (!(e instanceof HttpException))
        throw new InternalServerErrorException({
          error_code: 'internal_server_error',
          message: 'Internal server error',
        });
      throw e;
    }
  }

  @ApiOperation({ summary: 'Logs out the user' })
  @ApiResponse({ status: 200, description: 'Successfully logged out' })
  @Post('logout')
  async logout(@Res({ passthrough: true }) res) {
    try {
      this.authService.clearAuthCookies(res);
      return {
        message: 'Logged out successfully',
      };
    } catch (e) {
      if (!(e instanceof HttpException))
        throw new InternalServerErrorException({
          error_code: 'internal_server_error',
          message: 'Internal server error',
        });
      throw e;
    }
  }
}
