# Contribution

**Thank you in advance for your contribution!**

Please read [Auth0's contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md) before beginning work on your contribution here. 

## Environment setup

The best way we've found to develop gems locally is by using a local setting for your Bundler config. First, checkout the project locally:

```bash
$ pwd
/PROJECT_ROOT/
$ mkdir vendor # if one does not exist
$ echo "/vendor/" >> .gitignore
$ git clone git@github.com:auth0/omniauth-auth0.git vendor/omniauth-auth0
Cloning into 'vendor/omniauth-auth0'...
```

Now, run the following command in your project root directory:

```bash
$ bundle config --local local.omniauth-auth0 /PROJECT_ROOT/vendor/omniauth-auth0
You are replacing the current local value of local.omniauth-auth0, which is currently nil
$ bundle config
Settings are listed in order of priority. The top value will be used.
local.omniauth-auth0
Set for your local app (/PROJECT_ROOT/.bundle/config): "/PROJECT_ROOT/vendor/omniauth-auth0"
```

Finally, add or change the gem include to add a `github:` param:

```ruby
source 'https://rubygems.org'
# ...
# OmniAuth strategy for authenticating with Auth0
gem 'omniauth-auth0', github: 'auth0/omniauth-auth0'
#..
```

Now you should be able to make changes locally and have them reflected in your test app. Keep in mind you'll need to restart your app between changes.

[Great explanation for why this setup works well](https://rossta.net/blog/how-to-specify-local-ruby-gems-in-your-gemfile.html). 

## Testing

Tests should be added for additional or modified functionality and all tests should run successfully before submitting a PR. 

### Adding tests

All new tests should be added to the `/spec/omniauth` directory. Testing resources, like JSON fixtures, should be added to the `/spec/resources` directory.

### Running tests

Running tests is as simple as:

```bash
$ bundle exec rake spec
```

## Documentation

Documentation for this gem is primarily done at the code level. All new methods should include a docblock at least. 

## Code quality tools

Code quality is enforced across the entire gem with Rubocop:

```bash
$ bundle exec rake rubocop
```
