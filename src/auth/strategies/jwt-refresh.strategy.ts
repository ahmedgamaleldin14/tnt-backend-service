import { Strategy, ExtractJwt } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { type Request } from 'express';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AuthService } from '../services/auth.service';
import { REFRESH_TOKEN_COOKIE_NAME } from '../constants/auth.constants';
import { JwtTokenPayload } from '../interfaces/token-payload.interface';

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh',
) {
  constructor(
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        JwtRefreshStrategy.extractJWT,
      ]),
      ignoreExpiration: false,
      secretOrKey: configService.get('JWT_SECRET'),
      passReqToCallback: true,
    });
  }

  private static extractJWT(req: Request): string | null {
    if (
      req.cookies &&
      REFRESH_TOKEN_COOKIE_NAME in req.cookies &&
      req.cookies[REFRESH_TOKEN_COOKIE_NAME].length > 0
    ) {
      return req.cookies[REFRESH_TOKEN_COOKIE_NAME];
    }
    return null;
  }

  async validate(request: Request, payload: JwtTokenPayload) {
    const user = await this.authService.getUserById(payload.sub);
    if (!user) {
      return null;
    }
    request['user'] = user;
    return !!user;
  }
}
