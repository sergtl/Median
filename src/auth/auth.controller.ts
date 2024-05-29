import { Body, Controller, Post, Req, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOkResponse, ApiTags } from '@nestjs/swagger';
import { Request } from 'express';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { AuthEntity } from './entity/auth.entity';
import { AccessTokenGuard } from './guards/access-token.guard';
import { RefreshTokenGuard } from './guards/refresh-token.guard';

@Controller('auth')
@ApiTags('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @ApiOkResponse({ type: AuthEntity })
  login(@Body() { email, password }: LoginDto) {
    return this.authService.login(email, password);
  }

  @Post('refresh')
  @UseGuards(RefreshTokenGuard)
  @ApiOkResponse({ type: AuthEntity })
  refresh(@Req() req: Request) {
    const user = req.user;

    return this.authService.refreshTokens(user['sub'], user['refreshToken']);
  }

  @Post('logout')
  @UseGuards(AccessTokenGuard)
  @ApiBearerAuth()
  @ApiOkResponse()
  logout(@Req() req: Request) {
    return this.authService.logout(req.user['sub']);
  }
}
