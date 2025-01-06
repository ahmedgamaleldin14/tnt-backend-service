import { Controller, Get, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from 'src/auth/guards/jwt.guard';
import { CurrentUser } from 'src/auth/decorators/current-user.decorator';
import { UserInfo } from 'src/auth/interfaces/user-info.interface';
import {
  ApiOperation,
  ApiResponse,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';

@Controller('user')
export class UserController {
  @ApiOperation({ summary: "Fetches the current user's information" })
  @ApiResponse({
    status: 200,
    description: 'Successfully fetched user information',
  })
  @ApiUnauthorizedResponse({ description: 'Not authenticated' })
  @Get('me')
  @UseGuards(JwtAuthGuard)
  async me(@CurrentUser() user: UserInfo) {
    return user;
  }
}
