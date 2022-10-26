![Omniauth-auth0](https://cdn.auth0.com/website/sdks/banners/omniauth-auth0-banner.png)


[![CircleCI](https://img.shields.io/circleci/project/github/auth0/omniauth-auth0/master.svg)](https://circleci.com/gh/auth0/omniauth-auth0)
[![codecov](https://codecov.io/gh/auth0/omniauth-auth0/branch/master/graph/badge.svg)](https://codecov.io/gh/auth0/omniauth-auth0)
[![Gem Version](https://badge.fury.io/rb/omniauth-auth0.svg)](https://badge.fury.io/rb/omniauth-auth0)
[![MIT licensed](https://img.shields.io/dub/l/vibe-d.svg?style=flat)](https://github.com/auth0/omniauth-auth0/blob/master/LICENSE)

<div>
📚 <a href="#documentation">Documentation</a> - 🚀 <a href="#getting-started">Getting started</a> - 💻 <a href="https://www.rubydoc.info/gems/omniauth-auth0">API reference</a> - 💬 <a href="#feedback">Feedback</a>
</div>

## Documentation

- [Ruby on Rails Quickstart](https://auth0.com/docs/quickstart/webapp/rails)
- [Sample projects](https://github.com/auth0-samples/auth0-rubyonrails-sample)
- [API Reference](https://www.rubydoc.info/gems/omniauth-auth0)

## Getting started

### Installation

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

## Configure the SDK

Adding the SDK to your Rails app requires a few steps:

- [Create the configuration file](#create-the-configuration-file)
- [Create the initializer](#create-the-initializer)
- [Create the callback controller](#create-the-callback-controller)
- [Add routes](#add-routes)

### Create the configuration file

Create the file `./config/auth0.yml` within your application directory with the following content:

```yml
development:
  auth0_domain: <YOUR_DOMAIN>
  auth0_client_id: <YOUR_CLIENT_ID>
  auth0_client_secret: <YOUR AUTH0 CLIENT SECRET>
```

### Create the initializer

Create a new Ruby file in `./config/initializers/auth0.rb` to configure the OmniAuth middleware:

```ruby
AUTH0_CONFIG = Rails.application.config_for(:auth0)

Rails.application.config.middleware.use OmniAuth::Builder do
  provider(
    :auth0,
    AUTH0_CONFIG['auth0_client_id'],
    AUTH0_CONFIG['auth0_client_secret'],
    AUTH0_CONFIG['auth0_domain'],
    callback_path: '/auth/auth0/callback',
    authorize_params: {
      scope: 'openid profile'
    }
  )
end
```

### Create the callback controller

Create a new controller `./app/controllers/auth0_controller.rb` to handle the callback from Auth0.

> You can also run `rails generate controller auth0 callback failure logout --skip-assets --skip-helper --skip-routes --skip-template-engine` to scaffold this controller for you.

```ruby
# ./app/controllers/auth0_controller.rb
class Auth0Controller < ApplicationController
  def callback
    # OmniAuth stores the information returned from Auth0 and the IdP in request.env['omniauth.auth'].
    # In this code, you will pull the raw_info supplied from the id_token and assign it to the session.
    # Refer to https://github.com/auth0/omniauth-auth0/blob/master/EXAMPLES.md#example-of-the-resulting-authentication-hash for complete information on 'omniauth.auth' contents.
    auth_info = request.env['omniauth.auth']
    session[:userinfo] = auth_info['extra']['raw_info']

    # Redirect to the URL you want after successful auth
    redirect_to '/dashboard'
  end

  def failure
    # Handles failed authentication -- Show a failure page (you can also handle with a redirect)
    @error_msg = request.params['message']
  end

  def logout
    # you will finish this in a later step
  end
end
```

### Add routes

Finally, add the following routes to your `./config/routes.rb` file:

```ruby
Rails.application.routes.draw do
  # ..
  get '/auth/auth0/callback' => 'auth0#callback'
  get '/auth/failure' => 'auth0#failure'
  get '/auth/logout' => 'auth0#logout'
end
```

## Logging in

To redirect your users to Auth0 for authentication, redirect your users to the `/auth/auth0` endpoint of your app. One way to do this is to use a link or button on a page:

```html
<%= button_to 'Login', '/auth/auth0', method: :post %>
```

## Feedback

### Contributing

We appreciate feedback and contribution to this repo! Before you get started, please see the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/open-source-template/blob/master/CODE-OF-CONDUCT.md)
- [This repo's contribution guide](https://github.com/auth0/omniauth-auth0/blob/master/CONTRIBUTING.md)

### Raise an issue

To provide feedback or report a bug, please [raise an issue on our issue tracker](https://github.com/auth0/omniauth-auth0/issues).

### Vulnerability Reporting

Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

---

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_dark_mode.png" width="150">
    <source media="(prefers-color-scheme: light)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
    <img alt="Auth0 Logo" src="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
  </picture>
</p>
<p align="center">
  Auth0 is an easy to implement, adaptable authentication and authorization platform. To learn more checkout <a href="https://auth0.com/why-auth0">Why Auth0?</a>
</p>
<p align="center">
  This project is licensed under the MIT license. See the <a href="https://github.com/auth0/omniauth-auth0/blob/master/LICENSE"> LICENSE</a> file for more info.
</p>
