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
} from '../constants/auth.constants';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly prismaService: PrismaService,
  ) {}

  async getUserById(id: number): Promise<UserInfo> {
    const user = await this.prismaService.user.findUnique({ where: { id } });
    return AuthService.excludePassword(user);
  }

  async findUserByEmail(email: string): Promise<boolean> {
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
  ): Promise<UserInfo> {
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

    return AuthService.excludePassword(user);
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
  ): Promise<{
    access_token: string;
    refresh_token: string;
  }> {
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
  ): Promise<{
    access_token: string;
    refresh_token: string;
  }> {
    const payload = this.jwtService.verify(refreshToken);
    const user = await this.prismaService.user.findUnique({
      where: { id: payload.sub },
    });
    if (renewRefreshToken)
      return this.generateTokens(
        AuthService.excludePassword(user),
        refreshToken,
      );
    return this.generateTokens(AuthService.excludePassword(user));
  }
}
