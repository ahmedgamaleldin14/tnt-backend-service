type TokenUserInfo = {
  email: string;
  name: string;
};

export interface JwtTokenPayload {
  sub: number;
  user: TokenUserInfo;
}
