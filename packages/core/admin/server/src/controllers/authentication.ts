import type { Context, Next } from 'koa';
import passport from 'koa-passport';
import compose from 'koa-compose';
import * as crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import type { SignOptions } from 'jsonwebtoken';
import '@strapi/types';
import { errors } from '@strapi/utils';
import { getService } from '../utils/index';
import {
  REFRESH_COOKIE_NAME,
  buildCookieOptionsWithExpiry,
  getSessionManager,
  extractDeviceParams,
  generateDeviceId,
  getRefreshCookieOptions,
} from '../../../shared/utils/session-auth';

import {
  validateRegistrationInput,
  validateAdminRegistrationInput,
  validateRegistrationInfoQuery,
} from '../validation/authentication/register';
import validateForgotPasswordInput from '../validation/authentication/forgot-password';
import validateResetPasswordInput from '../validation/authentication/reset-password';
import validateLoginSessionInput from '../validation/authentication/login';

import type {
  ForgotPassword,
  Login,
  Register,
  RegistrationInfo,
  ResetPassword,
} from '../../../shared/contracts/authentication';
import { AdminUser } from '../../../shared/contracts/shared';

const { ApplicationError, ValidationError } = errors;

const TWO_FACTOR_CONTENT_TYPE_UID = 'plugin::deploy-plugin.admin-user-2fa';
const TWO_FACTOR_SETUP_TOKEN_PURPOSE = 'admin-2fa-setup';
const TWO_FACTOR_SETUP_TOKEN_AUDIENCE = 'strapi-admin-2fa-setup';
const TWO_FACTOR_SETUP_TOKEN_ISSUER = 'strapi-admin';
const TOTP_PERIOD_SECONDS = 30;
const TOTP_DIGITS = 6;

interface TwoFactorRecord {
  id: number | string;
  adminUserId: number | string;
  twoFactorSecret?: string | null;
  twoFactorEnabled?: boolean | null;
}

const toBoolean = (value: unknown, fallback = false) => {
  if (typeof value === 'boolean') {
    return value;
  }

  if (typeof value === 'number') {
    return value === 1;
  }

  if (typeof value === 'string') {
    return ['1', 'true', 'yes', 'on'].includes(value.toLowerCase());
  }

  return fallback;
};

const toInteger = (value: unknown, fallback: number) => {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number.parseInt(value, 10);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }

  return fallback;
};

const getTwoFactorConfig = () => {
  const configuredRequired = strapi.config.get('admin.auth.twoFactor.required');
  const required =
    configuredRequired === undefined
      ? toBoolean(process.env.ADMIN_2FA_REQUIRED, false)
      : toBoolean(configuredRequired, false);

  return {
    required,
    setupTokenExpiresIn:
      (strapi.config.get('admin.auth.twoFactor.setupTokenExpiresIn') as string | undefined) ||
      process.env.ADMIN_2FA_SETUP_TOKEN_EXPIRES_IN ||
      '5m',
    totpDriftSteps: Math.max(
      0,
      toInteger(
        strapi.config.get('admin.auth.twoFactor.totpDriftSteps') ??
          process.env.ADMIN_2FA_TOTP_DRIFT_STEPS,
        1
      )
    ),
  };
};

const getTwoFactorSetupSecret = () => {
  const setupSecret =
    process.env.ADMIN_2FA_SETUP_SECRET || (strapi.config.get('admin.auth.secret') as string);

  if (!setupSecret) {
    throw new Error('ADMIN_2FA_SETUP_SECRET or admin.auth.secret must be configured');
  }

  return setupSecret;
};

const createTwoFactorSetupToken = (user: AdminUser) => {
  const { setupTokenExpiresIn } = getTwoFactorConfig();
  const payload = {
    purpose: TWO_FACTOR_SETUP_TOKEN_PURPOSE,
    userId: String(user.id),
    email: user.email,
  };

  return jwt.sign(payload, getTwoFactorSetupSecret(), {
    audience: TWO_FACTOR_SETUP_TOKEN_AUDIENCE,
    expiresIn: setupTokenExpiresIn as SignOptions['expiresIn'],
    issuer: TWO_FACTOR_SETUP_TOKEN_ISSUER,
    subject: String(user.id),
  });
};

const normalizeAdminUserId = (userId: number | string) => {
  const numeric = typeof userId === 'number' ? userId : Number.parseInt(userId, 10);
  return Number.isFinite(numeric) ? numeric : userId;
};

const getTwoFactorRecord = async (userId: number | string): Promise<TwoFactorRecord | null> => {
  if (!strapi.contentTypes?.[TWO_FACTOR_CONTENT_TYPE_UID]) {
    return null;
  }

  return strapi.db.query(TWO_FACTOR_CONTENT_TYPE_UID).findOne({
    where: { adminUserId: normalizeAdminUserId(userId) },
  }) as Promise<TwoFactorRecord | null>;
};

const sendTwoFactorError = (
  ctx: Context,
  code: 'TWO_FACTOR_REQUIRED' | 'TWO_FACTOR_INVALID' | 'TWO_FACTOR_SETUP_REQUIRED',
  message: string,
  details: Record<string, unknown> = {}
) => {
  ctx.status = 401;
  ctx.body = {
    data: null,
    error: {
      status: 401,
      name: 'UnauthorizedError',
      message,
      details: {
        code,
        ...details,
      },
    },
  };
};

const decodeBase32 = (secret: string) => {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const normalizedSecret = secret.replace(/\s+/g, '').replace(/=+$/g, '').toUpperCase();
  const bytes: number[] = [];
  let value = 0;
  let bits = 0;

  for (const character of normalizedSecret) {
    const index = alphabet.indexOf(character);

    if (index === -1) {
      throw new Error('Invalid base32 secret');
    }

    value = (value << 5) | index;
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
};

const generateTotp = (secret: string, counter: number) => {
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));

  const digest = crypto.createHmac('sha1', decodeBase32(secret)).update(counterBuffer).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);

  return String(binary % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, '0');
};

const timingSafeEqual = (left: string, right: string) => {
  if (left.length !== right.length) {
    return false;
  }

  return crypto.timingSafeEqual(Buffer.from(left), Buffer.from(right));
};

const validateTotp = (passcode: unknown, secret: string, driftSteps: number) => {
  const normalizedPasscode = typeof passcode === 'string' ? passcode.replace(/\s+/g, '') : '';

  if (!new RegExp(`^\\d{${TOTP_DIGITS}}$`).test(normalizedPasscode)) {
    return false;
  }

  try {
    const currentCounter = Math.floor(Date.now() / 1000 / TOTP_PERIOD_SECONDS);

    for (let drift = -driftSteps; drift <= driftSteps; drift += 1) {
      if (timingSafeEqual(normalizedPasscode, generateTotp(secret, currentCounter + drift))) {
        return true;
      }
    }
  } catch (error) {
    strapi.log.warn('Failed to validate admin 2FA token', error);
  }

  return false;
};

export default {
  login: compose([
    async (ctx: Context, next: Next) => {
      await validateLoginSessionInput(ctx.request.body ?? {});
      return next();
    },
    (ctx: Context, next: Next) => {
      return passport.authenticate('local', { session: false }, (err, user, info) => {
        if (err) {
          strapi.eventHub.emit('admin.auth.error', { error: err, provider: 'local' });
          // if this is a recognized error, allow it to bubble up to user
          if (err.details?.code === 'LOGIN_NOT_ALLOWED') {
            throw err;
          }

          // for all other errors throw a generic error to prevent leaking info
          return ctx.notImplemented();
        }

        if (!user) {
          strapi.eventHub.emit('admin.auth.error', {
            error: new Error(info.message),
            provider: 'local',
          });
          throw new ApplicationError(info.message);
        }

        ctx.state.user = user;

        return next();
      })(ctx, next);
    },
    async (ctx: Context, next: Next) => {
      const { user } = ctx.state as { user: AdminUser };
      const config = getTwoFactorConfig();
      const record = await getTwoFactorRecord(user.id);
      const hasEnabledTwoFactor = Boolean(record?.twoFactorEnabled && record?.twoFactorSecret);

      if (hasEnabledTwoFactor) {
        const token = (ctx.request.body as Login.Request['body'])?.twoFactorToken;

        if (!token) {
          return sendTwoFactorError(
            ctx,
            'TWO_FACTOR_REQUIRED',
            'Two-factor authentication required'
          );
        }

        if (!validateTotp(token, record!.twoFactorSecret!, config.totpDriftSteps)) {
          strapi.eventHub.emit('admin.auth.error', {
            error: new Error('Invalid two-factor authentication token'),
            provider: 'local',
          });

          return sendTwoFactorError(
            ctx,
            'TWO_FACTOR_INVALID',
            'Invalid two-factor authentication code'
          );
        }

        return next();
      }

      if (config.required) {
        return sendTwoFactorError(
          ctx,
          'TWO_FACTOR_SETUP_REQUIRED',
          'Two-factor authentication setup required',
          { setupToken: createTwoFactorSetupToken(user) }
        );
      }

      return next();
    },
    async (ctx: Context) => {
      const { user } = ctx.state as { user: AdminUser };

      try {
        const sessionManager = getSessionManager();
        if (!sessionManager) {
          return ctx.internalServerError();
        }
        const userId = String(user.id);
        const { deviceId, rememberMe } = extractDeviceParams(ctx.request.body);

        const { token: refreshToken, absoluteExpiresAt } = await sessionManager(
          'admin'
        ).generateRefreshToken(userId, deviceId, {
          type: rememberMe ? 'refresh' : 'session',
        });

        const cookieOptions = buildCookieOptionsWithExpiry(
          rememberMe ? 'refresh' : 'session',
          absoluteExpiresAt,
          ctx.request.secure
        );
        ctx.cookies.set(REFRESH_COOKIE_NAME, refreshToken, cookieOptions);

        const accessResult = await sessionManager('admin').generateAccessToken(refreshToken);
        if ('error' in accessResult) {
          return ctx.internalServerError();
        }

        const { token: accessToken } = accessResult;

        ctx.body = {
          data: {
            token: accessToken,
            accessToken,
            user: getService('user').sanitizeUser(ctx.state.user),
          },
        } satisfies Login.Response;

        strapi.eventHub.emit('admin.auth.success', {
          user: getService('user').sanitizeUser(user),
          provider: 'local',
        });
      } catch (error) {
        strapi.log.error('Failed to create admin refresh session', error);
        return ctx.internalServerError();
      }
    },
  ]),

  async registrationInfo(ctx: Context) {
    await validateRegistrationInfoQuery(ctx.request.query);

    const { registrationToken } = ctx.request.query as RegistrationInfo.Request['query'];

    const registrationInfo = await getService('user').findRegistrationInfo(registrationToken);

    if (!registrationInfo) {
      throw new ValidationError('Invalid registrationToken');
    }

    ctx.body = { data: registrationInfo } satisfies RegistrationInfo.Response;
  },

  async register(ctx: Context) {
    const input = ctx.request.body as Register.Request['body'];

    await validateRegistrationInput(input);

    const user = await getService('user').register(input);

    try {
      const sessionManager = getSessionManager();
      if (!sessionManager) {
        return ctx.internalServerError();
      }
      const userId = String(user.id);
      const { deviceId, rememberMe } = extractDeviceParams(ctx.request.body);

      const { token: refreshToken, absoluteExpiresAt } = await sessionManager(
        'admin'
      ).generateRefreshToken(userId, deviceId, { type: rememberMe ? 'refresh' : 'session' });

      const cookieOptions = buildCookieOptionsWithExpiry(
        rememberMe ? 'refresh' : 'session',
        absoluteExpiresAt,
        ctx.request.secure
      );
      ctx.cookies.set(REFRESH_COOKIE_NAME, refreshToken, cookieOptions);

      const accessResult = await sessionManager('admin').generateAccessToken(refreshToken);
      if ('error' in accessResult) {
        return ctx.internalServerError();
      }

      const { token: accessToken } = accessResult;

      ctx.body = {
        data: {
          token: accessToken,
          accessToken,
          user: getService('user').sanitizeUser(user),
        },
      } satisfies Register.Response;
    } catch (error) {
      strapi.log.error('Failed to create admin refresh session during register', error);
      return ctx.internalServerError();
    }
  },

  async registerAdmin(ctx: Context) {
    const input = ctx.request.body as Register.Request['body'];

    await validateAdminRegistrationInput(input);

    const hasAdmin = await getService('user').exists();

    if (hasAdmin) {
      throw new ApplicationError('You cannot register a new super admin');
    }

    const superAdminRole = await getService('role').getSuperAdmin();

    if (!superAdminRole) {
      throw new ApplicationError(
        "Cannot register the first admin because the super admin role doesn't exist."
      );
    }

    const user = await getService('user').create({
      ...input,
      registrationToken: null,
      isActive: true,
      roles: superAdminRole ? [superAdminRole.id] : [],
    });

    strapi.telemetry.send('didCreateFirstAdmin');

    try {
      const sessionManager = getSessionManager();
      if (!sessionManager) {
        return ctx.internalServerError();
      }
      const userId = String(user.id);
      const { deviceId, rememberMe } = extractDeviceParams(ctx.request.body);

      const { token: refreshToken, absoluteExpiresAt } = await sessionManager(
        'admin'
      ).generateRefreshToken(userId, deviceId, { type: rememberMe ? 'refresh' : 'session' });

      const cookieOptions = buildCookieOptionsWithExpiry(
        rememberMe ? 'refresh' : 'session',
        absoluteExpiresAt,
        ctx.request.secure
      );
      ctx.cookies.set(REFRESH_COOKIE_NAME, refreshToken, cookieOptions);

      const accessResult = await sessionManager('admin').generateAccessToken(refreshToken);
      if ('error' in accessResult) {
        return ctx.internalServerError();
      }

      const { token: accessToken } = accessResult;

      ctx.body = {
        data: {
          token: accessToken,
          accessToken,
          user: getService('user').sanitizeUser(user),
        },
      };
    } catch (error) {
      strapi.log.error('Failed to create admin refresh session during register-admin', error);
      return ctx.internalServerError();
    }
  },

  async forgotPassword(ctx: Context) {
    const input = ctx.request.body as ForgotPassword.Request['body'];

    await validateForgotPasswordInput(input);

    getService('auth').forgotPassword(input);

    ctx.status = 204;
  },

  async resetPassword(ctx: Context) {
    const input = ctx.request.body as ResetPassword.Request['body'];

    await validateResetPasswordInput(input);

    const user = await getService('auth').resetPassword(input);

    // Issue a new admin refresh session and access token after password reset.
    try {
      const sessionManager = getSessionManager();
      if (!sessionManager) {
        return ctx.internalServerError();
      }

      const userId = String(user.id);
      const deviceId = generateDeviceId();

      // Invalidate all existing sessions before creating a new one
      await sessionManager('admin').invalidateRefreshToken(userId);

      const { token: refreshToken, absoluteExpiresAt } = await sessionManager(
        'admin'
      ).generateRefreshToken(userId, deviceId, { type: 'session' });

      // No rememberMe flow here; expire with session by default (session cookie)
      const cookieOptions = buildCookieOptionsWithExpiry(
        'session',
        absoluteExpiresAt,
        ctx.request.secure
      );
      ctx.cookies.set(REFRESH_COOKIE_NAME, refreshToken, cookieOptions);

      const accessResult = await sessionManager('admin').generateAccessToken(refreshToken);
      if ('error' in accessResult) {
        return ctx.internalServerError();
      }

      const { token } = accessResult;

      ctx.body = {
        data: {
          token,
          user: getService('user').sanitizeUser(user),
        },
      } satisfies ResetPassword.Response;
    } catch (err) {
      strapi.log.error('Failed to create admin refresh session during reset-password', err as any);
      return ctx.internalServerError();
    }
  },

  async accessToken(ctx: Context) {
    const refreshToken = ctx.cookies.get(REFRESH_COOKIE_NAME);

    if (!refreshToken) {
      return ctx.unauthorized('Missing refresh token');
    }

    try {
      const sessionManager = getSessionManager();
      if (!sessionManager) {
        return ctx.internalServerError();
      }

      // Single-use renewal: rotate on access exchange, then create access token
      // from the new refresh token
      const rotation = await sessionManager('admin').rotateRefreshToken(refreshToken);
      if ('error' in rotation) {
        return ctx.unauthorized('Invalid refresh token');
      }

      const result = await sessionManager('admin').generateAccessToken(rotation.token);
      if ('error' in result) {
        return ctx.unauthorized('Invalid refresh token');
      }

      const { token } = result;
      // Preserve session-vs-remember mode using rotation.type and rotation.absoluteExpiresAt
      const opts = buildCookieOptionsWithExpiry(
        rotation.type,
        rotation.absoluteExpiresAt,
        ctx.request.secure
      );

      ctx.cookies.set(REFRESH_COOKIE_NAME, rotation.token, opts);
      ctx.body = { data: { token } };
    } catch (err) {
      strapi.log.error('Failed to generate access token from refresh token', err as any);
      return ctx.internalServerError();
    }
  },

  async logout(ctx: Context) {
    const sanitizedUser = getService('user').sanitizeUser(ctx.state.user);
    strapi.eventHub.emit('admin.logout', { user: sanitizedUser });

    const bodyDeviceId = ctx.request.body?.deviceId as string | undefined;
    const deviceId = typeof bodyDeviceId === 'string' ? bodyDeviceId : undefined;

    // Clear cookie regardless of token validity
    ctx.cookies.set(REFRESH_COOKIE_NAME, '', {
      ...getRefreshCookieOptions(ctx.request.secure),
      expires: new Date(0),
    });

    try {
      const sessionManager = getSessionManager();
      if (sessionManager) {
        const userId = String(ctx.state.user.id);
        await sessionManager('admin').invalidateRefreshToken(userId, deviceId);
      }
    } catch (err) {
      strapi.log.error('Failed to revoke admin sessions during logout', err as any);
    }

    ctx.body = { data: {} };
  },
};
