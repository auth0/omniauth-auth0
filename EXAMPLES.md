* [Example of the resulting authentication hash](#example-of-the-resulting-authentication-hash)
* [Send additional authentication parameters](#send-additional-authentication-parameters)
* [Query Parameter Options](#query-parameter-options)
* [Auth0 Organizations](#auth0-organizations)
  - [Logging in with an Organization](#logging-in-with-an-organization)
  - [Validating Organizations when using Organization Login Prompt](#validating-organizations-when-using-organization-login-prompt)
  - [Accepting user invitations](#accepting-user-invitations)

### Example of the resulting authentication hash

The Auth0 strategy will provide the standard OmniAuth hash attributes:

- `:provider` - the name of the strategy, in this case `auth0`
- `:uid` - the user identifier
- `:info` - the result of the call to `/userinfo` using OmniAuth standard attributes
- `:credentials` - tokens requested and data
- `:extra` - Additional info obtained from calling `/userinfo` in the `:raw_info` property

```ruby
{
  :provider => 'auth0',
  :uid => 'auth0|USER_ID',
  :info => {
    :name => 'John Foo',
    :email => 'johnfoo@example.org',
    :nickname => 'john',
    :image => 'https://example.org/john.jpg'
  },
  :credentials => {
    :token => 'ACCESS_TOKEN',
    :expires_at => 1485373937,
    :expires => true,
    :refresh_token => 'REFRESH_TOKEN',
    :id_token => 'JWT_ID_TOKEN',
    :token_type => 'bearer',
  },
  :extra => {
    :raw_info => {
      :email => 'johnfoo@example.org',
      :email_verified => 'true',
      :name => 'John Foo',
      :picture => 'https://example.org/john.jpg',
      :user_id => 'auth0|USER_ID',
      :nickname => 'john',
      :created_at => '2014-07-15T17:19:50.387Z'
    }
  }
}
```

## Send additional authentication parameters

To send additional parameters during login, you can specify them when you register the provider:

```ruby
provider
  :auth0,
  ENV['AUTH0_CLIENT_ID'],
  ENV['AUTH0_CLIENT_SECRET'],
  ENV['AUTH0_DOMAIN'],
  {
    authorize_params: {
      scope: 'openid read:users write:order',
      audience: 'https://mydomain/api',
      max_age: 3600 # time in seconds authentication is valid
    }
  }
```

This will tell the strategy to send those parameters on every authentication request.

## Query Parameter Options

In some scenarios, you may need to pass specific query parameters to `/authorize`. The following parameters are available to enable this:

- `connection`
- `connection_scope`
- `prompt`
- `screen_hint` (only relevant to New Universal Login Experience)
- `organization`
- `invitation`
- `ui_locales` (only relevant to New Universal Login Experience)

Simply pass these query parameters to your OmniAuth redirect endpoint to enable their behavior.

## Auth0 Organizations

[Organizations](https://auth0.com/docs/organizations) is a set of features that provide better support for developers who build and maintain SaaS and Business-to-Business (B2B) applications.

Note that Organizations is currently only available to customers on our Enterprise and Startup subscription plans.

### Logging in with an Organization

Logging in with an Organization is as easy as passing the parameters to the authorize endpoint. You can do this with

```ruby
<%=
    button_to 'Login', 'auth/auth0',
    method: :post,
    params: {
      # Found in your Auth0 dashboard, under Organization settings:
      organization: '{AUTH0_ORGANIZATION}'
    }
%>
```

Alternatively you can configure the organization when you register the provider:

```ruby
provider
  :auth0,
  ENV['AUTH0_CLIENT_ID'],
  ENV['AUTH0_CLIENT_SECRET'],
  ENV['AUTH0_DOMAIN']
  {
    authorize_params: {
      scope: 'openid read:users',
      audience: 'https://{AUTH0_DOMAIN}/api',
      organization: '{AUTH0_ORGANIZATION}'
    }
  }
```

When passing `openid` to the scope and `organization` to the authorize params, you will receive an ID token on callback with the `org_id` claim. This claim is validated for you by the SDK.

### Validating Organizations when using Organization Login Prompt

When Organization login prompt is enabled on your application, but you haven't specified an Organization for the application's authorization endpoint, `org_id` or `org_name` claims will be present on the ID and access tokens, and should be validated to ensure that the value received is expected or known.

Normally, validating the issuer would be enough to ensure that the token was issued by Auth0, and this check is performed by the SDK. However, in the case of organizations, additional checks should be made so that the organization within an Auth0 tenant is expected.

In particular, the `org_id` and `org_name` claims should be checked to ensure it is a value that is already known to the application. This could be validated against a known list of organization IDs, or perhaps checked in conjunction with the current request URL. e.g. the sub-domain may hint at what organization should be used to validate the ID Token. For `org_id`, this should be a **case-sensitive, exact match check**. For `org_name`, this should be a **case-insentive check**.

The decision to validate the `org_id` or `org_name` claim is determined by the expected organization ID or name having an `org_` prefix.

Here is an example using it in your `callback` method

```ruby
def callback
  claims = request.env['omniauth.auth']['extra']['raw_info']

  validate_as_id = expected_org.start_with?('org_')

  if validate_as_id
    if claims["org_id"] && claims["org_id"] !== expected_org
      redirect_to '/unauthorized', status: 401
    else
      session[:userinfo] = claims
      redirect_to '/dashboard'
    end
  else
    if claims["org_name"] && claims["org_name"].downcase !== expected_org.downcase
      redirect_to '/unauthorized', status: 401
    else
      session[:userinfo] = claims
      redirect_to '/dashboard'
    end
  end
end
```

For more information, please read [Work with Tokens and Organizations](https://auth0.com/docs/organizations/using-tokens) on Auth0 Docs.

### Accepting user invitations

Auth0 Organizations allow users to be invited using emailed links, which will direct a user back to your application. The URL the user will arrive at is based on your configured `Application Login URI`, which you can change from your Application's settings inside the Auth0 dashboard.

When the user arrives at your application using an invite link, you can expect three query parameters to be provided: `invitation`, `organization`, and `organization_name`. These will always be delivered using a GET request.

You can then supply those parametrs to a `button_to` or `link_to` helper

```ruby
<%=
    button_to 'Login', 'auth/auth0',
    method: :post,
    params: {
      organization: '{YOUR_ORGANIZATION_ID}',
      invitation: '{INVITE_CODE}'
    }
%>
```
