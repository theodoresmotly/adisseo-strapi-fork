import * as React from 'react';
import { Box, Button, Flex, Main, Typography, Link } from '@strapi/design-system';
import camelCase from 'lodash/camelCase';
import { useIntl } from 'react-intl';
import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import * as yup from 'yup';

import { Form } from '../../../components/Form';
import { InputRenderer } from '../../../components/FormInputs/Renderer';
import { Logo } from '../../../components/UnauthenticatedLogo';
import {
  UnauthenticatedLayout,
  Column,
  LayoutContent,
} from '../../../layouts/UnauthenticatedLayout';
import { translatedErrors } from '../../../utils/translatedErrors';

// Pull in the default `login` function from your Auth (Strapi's admin usage)
import { useAuth } from '../../../features/Auth';

export interface LoginProps {
  children?: React.ReactNode;
}

// Validation schema for email/password
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

// Helper: call /deploy-plugin/tfa-check-status (POST) with { email }
async function check2FAStatus(email: string) {
  const resp = await fetch('/deploy-plugin/tfa-check-status', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  });

  if (!resp.ok) {
    const error = await resp.json();
    throw new Error(error?.message || 'Failed to check 2FA status');
  }

  return await resp.json(); // { twoFactorEnabled: boolean }
}

// Helper: call /deploy-plugin/tfa-check-code (POST) with { email, token }
async function verify2FACode(email: string, token: string) {
  const resp = await fetch('/deploy-plugin/tfa-check-code', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, token }),
  });

  const data = await resp.json();
  if (!resp.ok) {
    throw new Error(data?.message || 'Invalid 2FA token');
  }
  return data; // { valid: boolean }
}

// New helper: validate credentials (only checking email/password without proceeding to full login)
async function validateCredentials(email: string, password: string): Promise<void> {
  const resp = await fetch('/admin/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const data = await resp.json();
  if (!resp.ok) {
    throw new Error(data.error?.message || 'Invalid credentials');
  }
}

// Define credentials type with rememberMe as required boolean.
interface Credentials {
  email: string;
  password: string;
  rememberMe: boolean;
}

function LoginPage({ children }: LoginProps) {
  const [apiError, setApiError] = React.useState<string>();
  const [showTwoFactorInput, setShowTwoFactorInput] = React.useState(false);
  const [showTwoFactorSetup, setShowTwoFactorSetup] = React.useState(false);
  // Store the credentials so we can pass them to the 2FA setup flow
  const [credentials, setCredentials] = React.useState<Credentials | null>(null);

  const { formatMessage } = useIntl();
  const { search: searchString } = useLocation();
  const query = React.useMemo(() => new URLSearchParams(searchString), [searchString]);
  const navigate = useNavigate();

  // Default Strapi Admin `login` from useAuth
  const { login } = useAuth('Login', (auth) => auth);

  // Default login handler that calls the standard admin login endpoint.
  const defaultHandleLogin = async (body: { email: string; password: string; rememberMe: boolean }) => {
    setApiError(undefined);

    const res = await login(body);

    if ('error' in res) {
      const message = res.error.message ?? 'Something went wrong';

      if (camelCase(message).toLowerCase() === 'usernotactive') {
        navigate('/auth/oops');
        return;
      }

      setApiError(message);
    } else {
      // On success, navigate to the redirect URL (or homepage).
      const redirectTo = query.get('redirectTo');
      const redirectUrl = redirectTo ? decodeURIComponent(redirectTo) : '/';
      navigate(redirectUrl);
    }
  };

  //
  // Step A: user clicks "Login" with email/password.
  // First, we validate the credentials.
  // Then we check if 2FA is enabled.
  // - If 2FA is enabled, show the TFA input.
  // - If not, force mandatory 2FA setup.
  //
  const handleSubmitEmailPassword = async (values: {
    email: string;
    password: string;
    rememberMe?: boolean;
  }) => {
    setApiError(undefined);

    try {
      // Validate credentials (will throw if email/password are invalid).
      await validateCredentials(values.email, values.password);
      
      // Credentials are valid so now check 2FA status.
      const result = await check2FAStatus(values.email);
      if (result.twoFactorEnabled) {
        // 2FA is enabled → ask for the TFA code.
        setShowTwoFactorInput(true);
      } else {
        // 2FA is not enabled → store credentials and force mandatory 2FA setup.
        setCredentials({
          email: values.email,
          password: values.password,
          rememberMe: values.rememberMe ?? false,
        });
        setShowTwoFactorSetup(true);
      }
    } catch (err) {
      setApiError(err instanceof Error ? err.message : 'Login failed');
    }
  };

  //
  // Step B: for users who already have 2FA enabled, verify the TFA code.
  //
  const handleSubmitTwoFactor = async (values: {
    email: string;
    password: string;
    twoFactorToken?: string;
  }) => {
    setApiError(undefined);

    if (!values.twoFactorToken) {
      setApiError('2FA token is required');
      return;
    }

    try {
      const result = await verify2FACode(values.email, values.twoFactorToken);

      if (!result.valid) {
        setApiError('Invalid token');
        return;
      }

      await defaultHandleLogin({
        email: values.email,
        password: values.password,
        rememberMe: true,
      });
    } catch (err) {
      setApiError(err instanceof Error ? err.message : 'Invalid token');
    }
  };

  // If the user must complete 2FA setup, render the TwoFactorSetup component.
  if (showTwoFactorSetup && credentials) {
    return (
      <TwoFactorSetup
        email={credentials.email}
        onSetupComplete={async () => {
          // Once 2FA setup is complete, complete the login.
          await defaultHandleLogin(credentials);
        }}
      />
    );
  }

  // Otherwise, render the normal login form.
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
            initialValues={{
              email: '',
              password: '',
              rememberMe: false,
              twoFactorToken: '',
            }}
            onSubmit={(values) => {
              if (!showTwoFactorInput) {
                // Step A: Validate credentials and then check 2FA status.
                handleSubmitEmailPassword(values);
              } else {
                // Step B: Verify the TFA code and then log in.
                handleSubmitTwoFactor(values);
              }
            }}
            validationSchema={LOGIN_SCHEMA}
          >
            {() => (
              <Flex direction="column" alignItems="stretch" gap={6}>
                {!showTwoFactorInput && (
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

                {showTwoFactorInput && (
                  <InputRenderer
                    label="Enter your 2FA code"
                    name="twoFactorToken"
                    required
                    type="string"
                  />
                )}

                <Button fullWidth type="submit">
                  {showTwoFactorInput ? 'Verify 2FA & Login' : 'Login'}
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
  email: string;
  onSetupComplete: () => void;
}

// TwoFactorSetup forces the user to set up 2FA if it isn’t enabled.
function TwoFactorSetup({ email, onSetupComplete }: TwoFactorSetupProps) {
  const [qrCode, setQrCode] = React.useState<string>('');
  const [token, setToken] = React.useState<string>('');
  const [message2FA, setMessage2FA] = React.useState<string>('');
  // Instead of fetching admin user info, we use the email passed in.
  const [adminEmail] = React.useState<string>(email);
  const [isLoading, setIsLoading] = React.useState<boolean>(false);
  const [twoFactorEnabled, setTwoFactorEnabled] = React.useState<boolean>(false);
  const { formatMessage } = useIntl();

  // Check if 2FA is enabled (using the provided email).
  React.useEffect(() => {
    const checkStatus = async () => {
      if (!adminEmail) return;
      try {
        const res = await fetch('/deploy-plugin/tfa-check-status', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: adminEmail }),
        });
        if (!res.ok) {
          throw new Error('Failed to check 2FA status');
        }
        const data = await res.json();
        setTwoFactorEnabled(data.twoFactorEnabled);
      } catch (error: any) {
        console.error('Error checking 2FA status:', error);
        setTwoFactorEnabled(false);
      }
    };
    if (adminEmail) {
      checkStatus();
    }
  }, [adminEmail]);

  // If 2FA is not enabled, fetch the QR code.
  React.useEffect(() => {
    const fetchQr = async () => {
      if (!adminEmail) return;
      try {
        const res = await fetch('/deploy-plugin/tfa-setup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ userEmail: adminEmail }),
        });
        if (!res.ok) {
          throw new Error('Failed to fetch QR code');
        }
        const data = await res.json();
        setQrCode(data.qrCode);
      } catch (error: any) {
        console.error('Failed to fetch QR code:', error);
        setMessage2FA('Error fetching QR code.');
      }
    };
    if (!twoFactorEnabled && adminEmail) {
      fetchQr();
    }
  }, [twoFactorEnabled, adminEmail]);

  const verify = async () => {
    setIsLoading(true);
    try {
      const res = await fetch('/deploy-plugin/tfa-verify-setup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userEmail: adminEmail,
          token,
        }),
      });
      if (!res.ok) {
        throw new Error('Verification failed. Please check the TOTP code and try again.');
      }
      const data = await res.json();
      if (data.enabled) {
        setMessage2FA('2FA Enabled Successfully!');
        setTwoFactorEnabled(true);
        onSetupComplete();
      } else {
        setMessage2FA('Verification failed. Please try again.');
      }
    } catch (error: any) {
      setMessage2FA(error.message);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Box padding={6}>
      <Typography variant="alpha">Two-Factor Authentication Setup</Typography>
      <br />
      {message2FA && (
        <Typography textColor="danger600" variant="epsilon">
          {message2FA}
        </Typography>
      )}
      <br />
      {!qrCode ? (
        <Typography>Loading QR code...</Typography>
      ) : (
        <Box>
          <Box paddingTop={4}>
            <Typography variant="beta">
              Scan this QR code with your authenticator app:
            </Typography>
            <Box paddingTop={2}>
              <img
                src={qrCode}
                alt="QR Code for 2FA Setup"
                style={{ maxWidth: '200px', border: '1px solid #ccc' }}
              />
            </Box>
          </Box>
          <Box paddingTop={4}>
            <Typography>
              After scanning, enter the TOTP code from your authenticator app:
            </Typography>
            <Box paddingTop={2}>
              <input
                type="text"
                placeholder="Enter your TOTP code"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                style={{ padding: '8px', fontSize: '1rem', width: '100%' }}
              />
            </Box>
            <Box paddingTop={2}>
              <Button onClick={verify} disabled={isLoading}>
                Verify & Enable 2FA
              </Button>
            </Box>
          </Box>
        </Box>
      )}
    </Box>
  );
}

export { LoginPage as Login };
