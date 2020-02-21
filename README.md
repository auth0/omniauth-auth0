# OmniAuth Auth0

An [OmniAuth](https://github.com/intridea/omniauth) strategy for authenticating with [Auth0](https://auth0.com). This strategy is based on the [OmniAuth OAuth2](https://github.com/omniauth/omniauth-oauth2) strategy. 

**Important security note:** The parent library for this strategy currently has an unresolved security issue. Please see the discussion, including mitigations for Rails and non-Rails applications, [here](https://github.com/auth0/omniauth-auth0/issues/82).

[![CircleCI](https://img.shields.io/circleci/project/github/auth0/omniauth-auth0/master.svg)](https://circleci.com/gh/auth0/omniauth-auth0)
[![codecov](https://codecov.io/gh/auth0/omniauth-auth0/branch/master/graph/badge.svg)](https://codecov.io/gh/auth0/omniauth-auth0)
[![Gem Version](https://badge.fury.io/rb/omniauth-auth0.svg)](https://badge.fury.io/rb/omniauth-auth0)
[![MIT licensed](https://img.shields.io/dub/l/vibe-d.svg?style=flat)](https://github.com/auth0/omniauth-auth0/blob/master/LICENSE)

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
