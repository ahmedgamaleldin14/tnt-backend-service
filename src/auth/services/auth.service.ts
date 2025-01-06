import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';
import { User } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { JwtTokenPayload } from '../interfaces/token-payload.interface';
import { UserInfo } from '../interfaces/user-info.interface';
import {
  SALT_ROUNDS,
  REFRESH_TOKEN_EXPIRATION_S,
  ACCESS_TOKEN_COOKIE_NAME,
  REFRESH_TOKEN_COOKIE_NAME,
} from '../constants/auth.constants';
import { TokenPair } from '../interfaces/tokens.interface';
import { Response } from 'express';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly prismaService: PrismaService,
  ) {}

  async getUserById(id: number): Promise<UserInfo | null> {
    const user = await this.prismaService.user.findUnique({ where: { id } });
    if (user) {
      return AuthService.excludePassword(user);
    }
    return null;
  }

  async userExistsByEmail(email: string): Promise<boolean> {
    return !!(await this.prismaService.user.findUnique({ where: { email } }));
  }

  private static excludePassword(user: User): UserInfo {
    const passwordlessUser = {
      ...user,
    };
    delete passwordlessUser.password;
    return passwordlessUser;
  }

  async createUser(
    name: string,
    email: string,
    password: string,
  ): Promise<UserInfo | null> {
    const hashedPassword = await bcrypt.hash(
      password,
      await bcrypt.genSalt(SALT_ROUNDS),
    );
    const user = await this.prismaService.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
      },
    });

    if (user) {
      return AuthService.excludePassword(user);
    }
    return null;
  }

  async validateUser(
    username: string,
    password: string,
  ): Promise<UserInfo | null> {
    const user = await this.prismaService.user.findUnique({
      where: { email: username },
    });
    if (user) {
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (passwordMatch) {
        return AuthService.excludePassword(user);
      }
    }
    return null;
  }

  async generateTokens(
    user: UserInfo,
    existing_refresh_token?: string,
  ): Promise<TokenPair> {
    const payload: JwtTokenPayload = {
      sub: user.id,
      email: user.email,
      name: user.name,
    };
    const access_token = this.jwtService.sign(payload);
    const refresh_token =
      existing_refresh_token ||
      this.jwtService.sign(payload, {
        expiresIn: REFRESH_TOKEN_EXPIRATION_S,
      });
    return { access_token, refresh_token };
  }

  async refreshTokens(
    refreshToken: string,
    renewRefreshToken = false,
  ): Promise<TokenPair> {
    const payload = this.jwtService.verify(refreshToken);
    const user = await this.prismaService.user.findUnique({
      where: { id: payload.sub },
    });
    if (renewRefreshToken)
      return this.generateTokens(AuthService.excludePassword(user));
    return this.generateTokens(AuthService.excludePassword(user), refreshToken);
  }

  setAuthCookies(res: Response, tokens: TokenPair) {
    res.cookie(ACCESS_TOKEN_COOKIE_NAME, tokens.access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
    });
    res.cookie(REFRESH_TOKEN_COOKIE_NAME, tokens.refresh_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: REFRESH_TOKEN_EXPIRATION_S * 1000,
    });
  }

  clearAuthCookies(res: Response) {
    res.clearCookie(ACCESS_TOKEN_COOKIE_NAME);
    res.clearCookie(REFRESH_TOKEN_COOKIE_NAME);
  }
}
