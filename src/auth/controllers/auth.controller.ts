import {
  Body,
  Controller,
  Get,
  HttpException,
  HttpStatus,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { LoginUserDto } from '../dto/login-user.dto';
import { AuthService } from '../services/auth.service';
import { JwtRefreshAuthGuard } from '../guards/jwt-refresh.guard';
import { CreateUserDto } from '../dto/create-user.dto';
import { JwtAuthGuard } from '../guards/jwt.guard';
import { CurrentUser } from '../decorators/current-user.decorator';
import { UserInfo } from '../interfaces/user-info.interface';
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
    const user = await this.authService.validateUser(
      request.email,
      request.password,
    );
    if (user) {
      const tokens = await this.authService.generateTokens(user);

      this.authService.setAuthCookies(res, tokens);

      return user;
    }

    throw new HttpException(
      {
        error_code: 'invalid_credentials',
        message: 'Invalid credentials',
      },
      HttpStatus.UNAUTHORIZED,
    );
  }

  @ApiOperation({ summary: 'Refreshes the access token' })
  @ApiResponse({ status: 200, description: 'Successfully refreshed' })
  @ApiUnauthorizedResponse({ description: 'Invalid refresh token' })
  @Post('refresh')
  @UseGuards(JwtRefreshAuthGuard)
  async refresh(@Req() req, @Res({ passthrough: true }) res) {
    const refreshToken = req.cookies[REFRESH_TOKEN_COOKIE_NAME];
    const tokens = await this.authService.refreshTokens(refreshToken, false);
    this.authService.setAuthCookies(res, tokens);
  }

  @ApiOperation({ summary: 'Registers a new user' })
  @ApiResponse({ status: 200, description: 'Successfully registered' })
  @ApiBadRequestResponse({ description: 'Email already in use' })
  @Post('register')
  async register(@Body() request: CreateUserDto) {
    const name = request.name;
    const email = request.email;
    const password = request.password;
    const existingUser = await this.authService.userExistsByEmail(email);
    if (existingUser) {
      throw new HttpException(
        {
          error_code: 'email_in_use',
          message: 'Email already in use',
        },
        HttpStatus.BAD_REQUEST,
      );
    }

    const user = await this.authService.createUser(name, email, password);
    if (user) {
      return user;
    }
    throw new HttpException(
      {
        error_code: 'user_creation_failed',
        message: 'Failed to create user',
      },
      HttpStatus.INTERNAL_SERVER_ERROR,
    );
  }

  @ApiOperation({ summary: 'Logs out the user' })
  @ApiResponse({ status: 200, description: 'Successfully logged out' })
  @Post('logout')
  async logout(@Res({ passthrough: true }) res) {
    this.authService.clearAuthCookies(res);
    return {
      message: 'Logged out successfully',
    };
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  async me(@CurrentUser() user: UserInfo) {
    return user;
  }
}
