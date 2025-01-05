import {
  Body,
  Controller,
  Get,
  HttpStatus,
  Post,
  Res,
  UseGuards,
} from '@nestjs/common';
import { LoginUserDto } from '../dto/login-user.dto';
import { AuthService } from '../services/auth.service';
import {
  ACCESS_TOKEN_COOKIE_NAME,
  REFRESH_TOKEN_COOKIE_NAME,
  REFRESH_TOKEN_EXPIRATION_S,
} from '../constants/auth.constants';
import { JwtRefreshAuthGuard } from '../guards/jwt-refresh.guard';
import { CreateUserDto } from '../dto/create-user.dto';
import { JwtAuthGuard } from '../guards/jwt.guard';
import { CurrentUser } from '../decorators/current-user.decorator';
import { UserInfo } from '../interfaces/user-info.interface';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  private static setAuthCookies(res, tokens) {
    res.cookie(ACCESS_TOKEN_COOKIE_NAME, tokens.access_token, {
      httpOnly: true,
    });
    res.cookie(REFRESH_TOKEN_COOKIE_NAME, tokens.refresh_token, {
      httpOnly: true,
      maxAge: REFRESH_TOKEN_EXPIRATION_S * 1000,
    });
  }

  @Post('login')
  async login(@Body() request: LoginUserDto, @Res({ passthrough: true }) res) {
    const email = request.email;
    const password = request.password;
    const user = await this.authService.validateUser(email, password);
    if (user) {
      const tokens = await this.authService.generateTokens(user);

      AuthController.setAuthCookies(res, tokens);

      return user;
    }

    // TODO: log and return a standardized error response
    res.status(HttpStatus.UNAUTHORIZED).send({
      message: 'Invalid credentials',
    });
  }

  @Post('refresh')
  @UseGuards(JwtRefreshAuthGuard)
  async refresh(@Res({ passthrough: true }) res) {
    const refreshToken = res.cookies[REFRESH_TOKEN_COOKIE_NAME];
    const tokens = await this.authService.refreshTokens(refreshToken, false);
    AuthController.setAuthCookies(res, tokens);
  }

  @Post('register')
  async register(
    @Body() request: CreateUserDto,
    @Res({ passthrough: true }) res,
  ) {
    const name = request.name;
    const email = request.email;
    const password = request.password;
    const existingUser = await this.authService.findUserByEmail(email);
    if (existingUser) {
      // TODO: log and return a standardized error response
      res.status(HttpStatus.BAD_REQUEST).send({
        message: 'Email already in use',
      });
      return;
    }

    const user = await this.authService.createUser(name, email, password);
    if (user) {
      const tokens = await this.authService.generateTokens(user);
      AuthController.setAuthCookies(res, tokens);
      return user;
    }
    // TODO: log and return a standardized error response
    res.status(HttpStatus.INTERNAL_SERVER_ERROR).send({
      message: 'Failed to create user',
    });
  }

  @Post('logout')
  async logout(@Res({ passthrough: true }) res) {
    res.clearCookie(ACCESS_TOKEN_COOKIE_NAME);
    res.clearCookie(REFRESH_TOKEN_COOKIE_NAME);
    return {};
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  async me(@CurrentUser() user: UserInfo) {
    return user;
  }
}
