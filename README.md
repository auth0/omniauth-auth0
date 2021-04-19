# OmniAuth Auth0

An [OmniAuth](https://github.com/intridea/omniauth) strategy for authenticating with [Auth0](https://auth0.com). This strategy is based on the [OmniAuth OAuth2](https://github.com/omniauth/omniauth-oauth2) strategy.

> :warning:  **Important security note for v2:** This solution uses a 3rd party library that had a [security issue(s)](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-9284) in v2. Please review the details of the vulnerability, including [Auth0](https://github.com/auth0/omniauth-auth0/issues/82 ) and other recommended [mitigations](https://github.com/omniauth/omniauth/wiki/Resolving-CVE-2015-9284), before implementing the solution in v2.  **[Upgrading to v3](https://github.com/auth0/omniauth-auth0/pull/128) of this library resolves the issue.**

[![CircleCI](https://img.shields.io/circleci/project/github/auth0/omniauth-auth0/master.svg)](https://circleci.com/gh/auth0/omniauth-auth0)
[![codecov](https://codecov.io/gh/auth0/omniauth-auth0/branch/master/graph/badge.svg)](https://codecov.io/gh/auth0/omniauth-auth0)
[![Gem Version](https://badge.fury.io/rb/omniauth-auth0.svg)](https://badge.fury.io/rb/omniauth-auth0)
[![MIT licensed](https://img.shields.io/dub/l/vibe-d.svg?style=flat)](https://github.com/auth0/omniauth-auth0/blob/master/LICENSE)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fauth0%2Fomniauth-auth0.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fauth0%2Fomniauth-auth0?ref=badge_shield)

## Table of Contents

- [Documentation](#documentation)
- [Installation](#installation)
- [Getting Started](#getting-started)
- [Contribution](#contribution)
- [Support + Feedback](#support--feedback)
- [Vulnerability Reporting](#vulnerability-reporting)
- [What is Auth0](#what-is-auth0)
- [License](#license)

## Documentation

- [Ruby on Rails Quickstart](https://auth0.com/docs/quickstart/webapp/rails)
- [Sample projects](https://github.com/auth0-samples/auth0-rubyonrails-sample)
- [API Reference](https://www.rubydoc.info/gems/omniauth-auth0)

## Installation

Add the following line to your `Gemfile`:

```ruby
gem 'omniauth-auth0'
```

If you're using this strategy with Rails, also add the following for CSRF protection:

```ruby
gem 'omniauth-rails_csrf_protection'
```

Then install:

```bash
$ bundle install
```

See our [contributing guide](CONTRIBUTING.md) for information on local installation for development.

## Getting Started

To start processing authentication requests, the following steps must be performed:

1. Initialize the strategy
2. Configure the callback controller
3. Add the required routes
4. Trigger an authentication request

All of these tasks and more are covered in our [Ruby on Rails Quickstart](https://auth0.com/docs/quickstart/webapp/rails).

### Additional authentication parameters

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

... which will tell the strategy to send those parameters on every authentication request.

### Authentication hash

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

### Query Parameter Options

In some scenarios, you may need to pass specific query parameters to `/authorize`. The following parameters are available to enable this:

- `connection`
- `connection_scope`
- `prompt`
- `screen_hint` (only relevant to New Universal Login Experience)
- `organization`
- `invitation`

Simply pass these query parameters to your OmniAuth redirect endpoint to enable their behavior.

## Examples

### Auth0 Organizations

[Organizations](https://auth0.com/docs/organizations) is a set of features that provide better support for developers who build and maintain SaaS and Business-to-Business (B2B) applications.

Using Organizations, you can:

- Represent teams, business customers, partner companies, or any logical grouping of users that should have different ways of accessing your applications, as organizations.
- Manage their membership in a variety of ways, including user invitation.
- Configure branded, federated login flows for each organization.
- Implement role-based access control, such that users can have different roles when authenticating in the context of different organizations.
- Build administration capabilities into your products, using Organizations APIs, so that those businesses can manage their own organizations.

Note that Organizations is currently only available to customers on our Enterprise and Startup subscription plans.

#### Logging in with an Organization

Logging in with an Organization is as easy as passing the parameters to the authorize endpoint.  You can do this with 

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

When passing `openid` to the scope and `organization` to the authorize params, you will receive an ID token on callback with the `org_id` claim.  This claim is validated for you by the SDK.

#### Validating Organizations when using Organization Login Prompt

When Organization login prompt is enabled on your application, but you haven't specified an Organization for the application's authorization endpoint, the `org_id` claim will be present on the ID token, and should be validated to ensure that the value received is expected or known.

Normally, validating the issuer would be enough to ensure that the token was issued by Auth0, and this check is performed by the SDK. However, in the case of organizations, additional checks should be made so that the organization within an Auth0 tenant is expected.

In particular, the `org_id` claim should be checked to ensure it is a value that is already known to the application. This could be validated against a known list of organization IDs, or perhaps checked in conjunction with the current request URL. e.g. the sub-domain may hint at what organization should be used to validate the ID Token.

Here is an example using it in your `callback` method

```ruby
  def callback
    claims = request.env['omniauth.auth']['extra']['raw_info']

    if claims["org"] && claims["org"] !== expected_org
      redirect_to '/unauthorized', status: 401
    else
      session[:userinfo] = claims
      redirect_to '/dashboard'
    end
  end
```

For more information, please read [Work with Tokens and Organizations](https://auth0.com/docs/organizations/using-tokens) on Auth0 Docs.

#### Accepting user invitations

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

## Contribution

We appreciate feedback and contribution to this repo! Before you get started, please see the following:

- [Auth0's contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's Code of Conduct](https://github.com/auth0/open-source-template/blob/master/CODE-OF-CONDUCT.md)
- [This repo's contribution guide](CONTRIBUTING.md)

## Support + Feedback

- Use [Community](https://community.auth0.com/) for usage, questions, specific cases.
- Use [Issues](https://github.com/auth0/omniauth-auth0/issues) here for code-level support and bug reports.
- Paid customers can use [Support](https://support.auth0.com/) to submit a trouble ticket for production-affecting issues.

## Vulnerability Reporting

Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## What is Auth0?

Auth0 helps you to easily:

- implement authentication with multiple identity providers, including social (e.g., Google, Facebook, Microsoft, LinkedIn, GitHub, Twitter, etc), or enterprise (e.g., Windows Azure AD, Google Apps, Active Directory, ADFS, SAML, etc.)
- log in users with username/password databases, passwordless, or multi-factor authentication
- link multiple user accounts together
- generate signed JSON Web Tokens to authorize your API calls and flow the user identity securely
- access demographics and analytics detailing how, when, and where users are logging in
- enrich user profiles from other data sources using customizable JavaScript rules

[Why Auth0?](https://auth0.com/why-auth0)

## License

The OmniAuth Auth0 strategy is licensed under MIT - [LICENSE](LICENSE)


[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fauth0%2Fomniauth-auth0.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fauth0%2Fomniauth-auth0?ref=badge_large)
