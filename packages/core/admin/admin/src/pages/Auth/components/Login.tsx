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

//
// 1) Helper: call /deploy-plugin/tfa-check-status (POST) with { email }
//    returns { twoFactorEnabled: boolean }.
//
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

  return await resp.json(); // { twoFactorEnabled: true/false }
}

//
// 2) Helper: call /deploy-plugin/tfa-check-code (POST) with { email, token }
//    returns { valid: boolean }.
//
async function verify2FACode(email: string, token: string) {
  const resp = await fetch('/deploy-plugin/tfa-check-code', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, token }),
  });

  const data = await resp.json();
  if (!resp.ok) {
    // For example, server might respond with 400 or 401
    throw new Error(data?.message || 'Invalid 2FA token');
  }
  // data = { valid: boolean }
  return data;
}

function Login({ children }: LoginProps) {
  const [apiError, setApiError] = React.useState<string>();
  const [showTwoFactorInput, setShowTwoFactorInput] = React.useState(false);

  const { formatMessage } = useIntl();
  const { search: searchString } = useLocation();
  const query = React.useMemo(() => new URLSearchParams(searchString), [searchString]);
  const navigate = useNavigate();

  // Default Strapi Admin `login` from useAuth
  const { login } = useAuth('Login', (auth) => auth);

  //
  // Default handleLogin from your snippet:
  // Calls the standard admin login endpoint.
  //
  const defaultHandleLogin = async (body: Parameters<typeof login>[0]) => {
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
      // success
      const redirectTo = query.get('redirectTo');
      const redirectUrl = redirectTo ? decodeURIComponent(redirectTo) : '/';
      navigate(redirectUrl);
    }
  };

  //
  // Step A: user clicks "Login" with email/password => check 2FA
  //
  const handleSubmitEmailPassword = async (values: {
    email: string;
    password: string;
    rememberMe?: boolean;
  }) => {
    setApiError(undefined);

    try {
      // 1) Check if 2FA is enabled for this user
      const result = await check2FAStatus(values.email);
      if (result.twoFactorEnabled) {
        // 2FA is required -> show the TFA input
        setShowTwoFactorInput(true);
      } else {
        // 2FA is not required -> do default handleLogin
        await defaultHandleLogin({
          email: values.email,
          password: values.password,
          rememberMe: values.rememberMe || false,
        });
      }
    } catch (err) {
      setApiError(err instanceof Error ? err.message : 'Login failed');
    }
  };

  //
  // Step B: user enters TFA code => verify via /tfa-check-code
  // If valid, do default handleLogin
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
      // 1) Check the token
      const result = await verify2FACode(values.email, values.twoFactorToken);

      if (!result.valid) {
        // If the server says { valid: false }, show error
        setApiError('Invalid token');
        return;
      }

      // 2) If valid => call the normal handleLogin
      await defaultHandleLogin({
        email: values.email,
        password: values.password,
        rememberMe: false,
      });
    } catch (err) {
      setApiError(err instanceof Error ? err.message : 'Invalid token');
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
                {formatMessage({
                  id: 'Auth.form.welcome.title',
                  defaultMessage: 'Welcome!',
                })}
                &nbsp;- Adisseo
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
              <Typography
                id="global-form-error"
                role="alert"
                tabIndex={-1}
                textColor="danger600"
              >
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
                // Step A: no TFA input shown => check 2FA status
                handleSubmitEmailPassword(values);
              } else {
                // Step B: user is entering 2FA code => verify + then login
                handleSubmitTwoFactor(values);
              }
            }}
            validationSchema={LOGIN_SCHEMA}
          >
            {() => (
              <Flex direction="column" alignItems="stretch" gap={6}>
                {/* Step A fields */}
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

                {/* Step B field: TFA code */}
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

export { Login };
