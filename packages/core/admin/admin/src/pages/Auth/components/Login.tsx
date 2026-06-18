import * as React from 'react';
import { Box, Button, Flex, Link, Main, Typography } from '@strapi/design-system';
import camelCase from 'lodash/camelCase';
import { useIntl } from 'react-intl';
import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import * as yup from 'yup';

import { Form } from '../../../components/Form';
import { InputRenderer } from '../../../components/FormInputs/Renderer';
import { Logo } from '../../../components/UnauthenticatedLogo';
import {
  Column,
  LayoutContent,
  UnauthenticatedLayout,
} from '../../../layouts/UnauthenticatedLayout';
import { translatedErrors } from '../../../utils/translatedErrors';

import { useAuth } from '../../../features/Auth';
import { useTypedDispatch } from '../../../core/store/hooks';
import { logout as logoutAction } from '../../../reducer';

export interface LoginProps {
  children?: React.ReactNode;
}

const LOGIN_SCHEMA = yup.object().shape({
  email: yup
    .string()
    .nullable()
    .email({
      id: translatedErrors.email.id,
      defaultMessage: 'Not a valid email',
    })
    .required(translatedErrors.required),
  password: yup.string().required(translatedErrors.required).nullable(),
  rememberMe: yup.bool().nullable(),
});

interface Credentials {
  email: string;
  password: string;
  rememberMe: boolean;
}

interface LoginFormValues extends Credentials {
  twoFactorToken?: string;
}

interface ApiErrorWithDetails {
  message?: string;
  details?: {
    code?: string;
    setupToken?: string;
  };
}

type LoginMode = 'credentials' | 'totp' | 'setup';

const getErrorDetails = (error: unknown) => {
  const apiError = error as ApiErrorWithDetails;

  return {
    code: apiError.details?.code,
    message: apiError.message ?? 'Something went wrong',
    setupToken: apiError.details?.setupToken,
  };
};

const getResponseErrorMessage = async (response: Response, fallback: string) => {
  try {
    const data = await response.json();

    return data?.error?.message || data?.message || fallback;
  } catch {
    return fallback;
  }
};

function LoginPage({ children }: LoginProps) {
  const [apiError, setApiError] = React.useState<string>();
  const [mode, setMode] = React.useState<LoginMode>('credentials');
  const [credentials, setCredentials] = React.useState<Credentials | null>(null);
  const [setupToken, setSetupToken] = React.useState<string>();

  const { formatMessage } = useIntl();
  const { search: searchString } = useLocation();
  const query = React.useMemo(() => new URLSearchParams(searchString), [searchString]);
  const navigate = useNavigate();
  const { login } = useAuth('Login', (auth) => auth);
  const dispatch = useTypedDispatch();

  const redirectAfterLogin = React.useCallback(() => {
    const redirectTo = query.get('redirectTo');
    const redirectUrl = redirectTo ? decodeURIComponent(redirectTo) : '/';

    navigate(redirectUrl);
  }, [navigate, query]);

  const handleLoginError = React.useCallback(
    (error: unknown, submittedCredentials: Credentials) => {
      const { code, message, setupToken: nextSetupToken } = getErrorDetails(error);

      if (camelCase(message).toLowerCase() === 'usernotactive') {
        navigate('/auth/oops');
        return;
      }

      if (code === 'TWO_FACTOR_REQUIRED') {
        dispatch(logoutAction());
        setCredentials(submittedCredentials);
        setSetupToken(undefined);
        setMode('totp');
        setApiError(undefined);
        return;
      }

      if (code === 'TWO_FACTOR_INVALID') {
        dispatch(logoutAction());
        setCredentials(submittedCredentials);
        setSetupToken(undefined);
        setMode('totp');
        setApiError('Invalid two-factor authentication code');
        return;
      }

      if (code === 'TWO_FACTOR_SETUP_REQUIRED') {
        if (typeof nextSetupToken !== 'string' || nextSetupToken.length === 0) {
          setApiError('Two-factor setup is required, but the setup token was not returned.');
          return;
        }

        dispatch(logoutAction());
        setCredentials(submittedCredentials);
        setSetupToken(nextSetupToken);
        setMode('setup');
        setApiError(undefined);
        return;
      }

      setApiError(message);
    },
    [dispatch, navigate]
  );

  const completeLogin = React.useCallback(
    async (body: Credentials & { twoFactorToken?: string }) => {
      setApiError(undefined);

      const res = await login(body);

      if ('error' in res) {
        const { twoFactorToken: _twoFactorToken, ...submittedCredentials } = body;
        handleLoginError(res.error, submittedCredentials);
        return;
      }

      redirectAfterLogin();
    },
    [handleLoginError, login, redirectAfterLogin]
  );

  const handleSubmitCredentials = async (values: LoginFormValues) => {
    await completeLogin({
      email: values.email,
      password: values.password,
      rememberMe: values.rememberMe ?? false,
    });
  };

  const handleSubmitTwoFactor = async (values: LoginFormValues) => {
    if (!credentials) {
      setMode('credentials');
      setApiError('Please enter your email and password again.');
      return;
    }

    if (!values.twoFactorToken) {
      setApiError('Two-factor authentication code is required');
      return;
    }

    await completeLogin({
      ...credentials,
      twoFactorToken: values.twoFactorToken,
    });
  };

  const handleSetupComplete = async (twoFactorToken: string) => {
    if (!credentials) {
      setMode('credentials');
      setApiError('Please enter your email and password again.');
      return;
    }

    await completeLogin({
      ...credentials,
      twoFactorToken,
    });
  };

  const initialValues = React.useMemo<LoginFormValues>(
    () => ({
      email: credentials?.email ?? '',
      password: credentials?.password ?? '',
      rememberMe: credentials?.rememberMe ?? false,
      twoFactorToken: '',
    }),
    [credentials]
  );

  if (mode === 'setup' && setupToken) {
    return <TwoFactorSetup setupToken={setupToken} onSetupComplete={handleSetupComplete} />;
  }

  return (
    <UnauthenticatedLayout>
      <Main>
        <LayoutContent>
          <Column>
            <Logo />
            <Box paddingTop={6} paddingBottom={1}>
              <Typography variant="alpha" tag="h1" textAlign="center">
                {formatMessage({
                  id: 'Auth.form.welcome.title',
                  defaultMessage: 'Welcome!',
                })}
                &nbsp;
                <br />
                Adisseo
              </Typography>
            </Box>
            <Box paddingBottom={7}>
              <Typography
                variant="epsilon"
                textColor="neutral600"
                textAlign="center"
                display="block"
              >
                {formatMessage({
                  id: 'Auth.form.welcome.subtitle',
                  defaultMessage: 'Log in to your Strapi account',
                })}
              </Typography>
            </Box>
            {apiError && (
              <Typography id="global-form-error" role="alert" tabIndex={-1} textColor="danger600">
                {apiError}
              </Typography>
            )}
          </Column>

          <Form
            method="PUT"
            initialValues={initialValues}
            onSubmit={(values) => {
              if (mode === 'credentials') {
                handleSubmitCredentials(values as LoginFormValues);
              } else {
                handleSubmitTwoFactor(values as LoginFormValues);
              }
            }}
            validationSchema={LOGIN_SCHEMA}
          >
            {() => (
              <Flex direction="column" alignItems="stretch" gap={6}>
                {mode === 'credentials' && (
                  <>
                    <InputRenderer
                      label={formatMessage({
                        id: 'Auth.form.email.label',
                        defaultMessage: 'Email',
                      })}
                      name="email"
                      placeholder={formatMessage({
                        id: 'Auth.form.email.placeholder',
                        defaultMessage: 'kai@doe.com',
                      })}
                      required
                      type="string"
                    />
                    <InputRenderer
                      label={formatMessage({
                        id: 'global.password',
                        defaultMessage: 'Password',
                      })}
                      name="password"
                      required
                      type="password"
                    />
                    <InputRenderer
                      label={formatMessage({
                        id: 'Auth.form.rememberMe.label',
                        defaultMessage: 'Remember me',
                      })}
                      name="rememberMe"
                      type="checkbox"
                    />
                  </>
                )}

                {mode === 'totp' && (
                  <InputRenderer
                    label="Two-factor authentication code"
                    name="twoFactorToken"
                    required
                    type="string"
                  />
                )}

                <Button fullWidth type="submit">
                  {mode === 'totp' ? 'Verify 2FA and log in' : 'Login'}
                </Button>
              </Flex>
            )}
          </Form>
          {children}
        </LayoutContent>
        <Flex justifyContent="center">
          <Box paddingTop={4}>
            <Link isExternal={false} tag={NavLink} to="/auth/forgot-password">
              {formatMessage({
                id: 'Auth.link.forgot-password',
                defaultMessage: 'Forgot your password?',
              })}
            </Link>
          </Box>
        </Flex>
      </Main>
    </UnauthenticatedLayout>
  );
}

interface TwoFactorSetupProps {
  setupToken: string;
  onSetupComplete: (twoFactorToken: string) => Promise<void>;
}

function TwoFactorSetup({ setupToken, onSetupComplete }: TwoFactorSetupProps) {
  const [qrCode, setQrCode] = React.useState<string>('');
  const [token, setToken] = React.useState<string>('');
  const [message, setMessage] = React.useState<string>('');
  const [isLoading, setIsLoading] = React.useState<boolean>(false);
  const { formatMessage } = useIntl();

  React.useEffect(() => {
    let cancelled = false;

    const fetchQrCode = async () => {
      setMessage('');
      setIsLoading(true);

      try {
        const response = await fetch('/deploy-plugin/tfa-setup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ setupToken }),
        });

        if (!response.ok) {
          throw new Error(await getResponseErrorMessage(response, 'Failed to start 2FA setup'));
        }

        const data = await response.json();

        if (!cancelled) {
          setQrCode(data.qrCode);
        }
      } catch (error) {
        if (!cancelled) {
          setMessage(error instanceof Error ? error.message : 'Failed to start 2FA setup');
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false);
        }
      }
    };

    fetchQrCode();

    return () => {
      cancelled = true;
    };
  }, [setupToken]);

  const verify = async () => {
    if (!token) {
      setMessage('Two-factor authentication code is required');
      return;
    }

    setMessage('');
    setIsLoading(true);

    try {
      const response = await fetch('/deploy-plugin/tfa-verify-setup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          setupToken,
          token,
        }),
      });

      if (!response.ok) {
        throw new Error(
          await getResponseErrorMessage(
            response,
            'Verification failed. Please check the code and try again.'
          )
        );
      }

      const data = await response.json();

      if (!data.enabled) {
        throw new Error('Verification failed. Please check the code and try again.');
      }

      await onSetupComplete(token);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Verification failed');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <UnauthenticatedLayout>
      <Main>
        <LayoutContent>
          <Column>
            <Logo />
            <Box paddingTop={6} paddingBottom={1}>
              <Typography variant="alpha" tag="h1" textAlign="center">
                Two-factor authentication
              </Typography>
            </Box>
            <Box paddingBottom={7}>
              <Typography
                variant="epsilon"
                textColor="neutral600"
                textAlign="center"
                display="block"
              >
                {formatMessage({
                  id: 'Auth.form.welcome.subtitle',
                  defaultMessage: 'Log in to your Strapi account',
                })}
              </Typography>
            </Box>
            {message && (
              <Typography id="global-form-error" role="alert" tabIndex={-1} textColor="danger600">
                {message}
              </Typography>
            )}
          </Column>

          <Flex direction="column" alignItems="stretch" gap={6}>
            {!qrCode ? (
              <Typography textColor="neutral600">
                {isLoading ? 'Loading QR code...' : 'Unable to load QR code.'}
              </Typography>
            ) : (
              <>
                <Flex justifyContent="center">
                  <img
                    src={qrCode}
                    alt="QR code for two-factor authentication setup"
                    style={{ maxWidth: '200px', border: '1px solid #dcdce4' }}
                  />
                </Flex>
                <Box>
                  <input
                    type="text"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    placeholder="Enter your authentication code"
                    value={token}
                    onChange={(event) => setToken(event.target.value)}
                    style={{
                      width: '100%',
                      padding: '12px',
                      border: '1px solid #dcdce4',
                      borderRadius: '4px',
                      fontSize: '1rem',
                    }}
                  />
                </Box>
                <Button onClick={verify} disabled={isLoading} fullWidth>
                  Verify and log in
                </Button>
              </>
            )}
          </Flex>
        </LayoutContent>
      </Main>
    </UnauthenticatedLayout>
  );
}

export { LoginPage as Login };
