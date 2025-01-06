import { Strategy, ExtractJwt } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { type Request } from 'express';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AuthService } from '../services/auth.service';
import { ACCESS_TOKEN_COOKIE_NAME } from '../constants/auth.constants';
import { JwtTokenPayload } from '../interfaces/token-payload.interface';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([JwtStrategy.extractJWT]),
      ignoreExpiration: false,
      secretOrKey: configService.get('JWT_SECRET'),
    });
  }

  private static extractJWT(req: Request): string | null {
    if (
      req.cookies &&
      ACCESS_TOKEN_COOKIE_NAME in req.cookies &&
      req.cookies[ACCESS_TOKEN_COOKIE_NAME].length > 0
    ) {
      return req.cookies[ACCESS_TOKEN_COOKIE_NAME];
    }
    return null;
  }

  async validate(payload: JwtTokenPayload) {
    return this.authService.getUserById(payload.sub);
  }
}
