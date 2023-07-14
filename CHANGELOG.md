# Change Log

## [v3.2.0](https://github.com/auth0/omniauth-auth0/tree/v3.2.0) (2023-07-14)
[Full Changelog](https://github.com/auth0/omniauth-auth0/compare/v3.1.0...v3.2.0)

**Added**
- [SDK-4410] Support Organization Name in JWT validation [\#184](https://github.com/auth0/omniauth-auth0/pull/184) ([stevehobbsdev](https://github.com/stevehobbsdev))

**Fixed**
- fix: upgrade to Sinatra 3 and use Rack::Session::Cookie in tests [\#165](https://github.com/auth0/omniauth-auth0/pull/165) ([stevehobbsdev](https://github.com/stevehobbsdev))

## [v3.1.1](https://github.com/auth0/omniauth-auth0/tree/v3.1.1) (2023-03-01)
[Full Changelog](https://github.com/auth0/omniauth-auth0/compare/v3.1.0...v3.1.1)

**Fixed**
- fix: upgrade to Sinatra 3 and use Rack::Session::Cookie in tests [\#165](https://github.com/auth0/omniauth-auth0/pull/165) ([stevehobbsdev](https://github.com/stevehobbsdev))

## [v3.1.0](https://github.com/auth0/omniauth-auth0/tree/v3.1.0) (2022-11-04)

[Full Changelog](https://github.com/auth0/omniauth-auth0/compare/v3.0.0...v3.1.0)

**Added**

- Add ui_locales to permitted params [\#135](https://github.com/auth0/omniauth-auth0/pull/135) ([martijn](https://github.com/martijn))

**Changed**

- Store plain Hash in session['authorize_params'] [\#150](https://github.com/auth0/omniauth-auth0/pull/150) ([santry](https://github.com/santry))
- Redesign readme to match new style [\#148](https://github.com/auth0/omniauth-auth0/pull/148) ([stevehobbsdev](https://github.com/stevehobbsdev))

**Fixed**

- Fix authentication hash link in code sample [\#153](https://github.com/auth0/omniauth-auth0/pull/153) ([ewanharris](https://github.com/ewanharris))

**Security**

- [Snyk] Fix for 1 vulnerabilities [\#149](https://github.com/auth0/omniauth-auth0/pull/149) ([snyk-bot](https://github.com/snyk-bot))
- Bump addressable from 2.7.0 to 2.8.0 [\#133](https://github.com/auth0/omniauth-auth0/pull/133) ([dependabot[bot]](https://github.com/apps/dependabot))
- [Snyk] Security upgrade webmock from 3.12.2 to 3.12.2 [\#134](https://github.com/auth0/omniauth-auth0/pull/134) ([snyk-bot](https://github.com/snyk-bot))

## [v3.0.0](https://github.com/auth0/omniauth-auth0/tree/v3.0.0) (2021-04-14)

Version 3.0 introduces [Omniauth v2.0](https://github.com/omniauth/omniauth/releases/tag/v2.0.0) which addresses [CVE-2015-9284](https://nvd.nist.gov/vuln/detail/CVE-2015-9284). Omniauth now defaults to only allow `POST` as the allowed request_phase method. This was previously handled through the recommended [mitigation](https://github.com/omniauth/omniauth/wiki/Resolving-CVE-2015-9284) using the `omniauth-rails_csrf_protection v0.x.x` gem to provide CSRF protection.

### Upgrading to omniauth-rails_csrf_protection v1.0.0

If you are using `omniauth-rails_csrf_protection` to provide CSRF protection, you will need to be upgrade to `1.x.x`.

### BREAKING CHANGES

Now that OmniAuth now defaults to only `POST` as the allowed request_phase method, if you aren't already, you will need to convert any login links to use [form helpers](https://api.rubyonrails.org/classes/ActionView/Helpers/FormHelper.html#method-i-form_for) with the `POST` method.

```html+ruby
# OLD -- GET request
<a href='/auth/auth0'>Login</a>

# NEW Example #1 -- POST request
<%= link_to 'Login', 'auth/auth0', method: :post %>

# NEW Example #2 -- POST request
<%= button_to 'Login', 'auth/auth0', method: :post %>

# NEW Example #3 -- POST request
<%= form_tag('/auth/auth0', method: :post) do %>
  <button type='submit'></button>
<% end %>
```

### Allowing GET Requests

In the scenario you absolutely must use GET requests as an allowed request method for authentication, you can override the protection provided with the following config override:

```ruby
# Allowing GET requests will expose you to CVE-2015-9284
OmniAuth.config.allowed_request_methods = [:get, :post]
```

## [v2.6.0](https://github.com/auth0/omniauth-auth0/tree/v2.6.0) (2021-04-01)

[Full Changelog](https://github.com/auth0/omniauth-auth0/compare/v2.5.0...v2.6.0)

**Added**

- Org Support [SDK-2395] [\#124](https://github.com/auth0/omniauth-auth0/pull/124) ([davidpatrick](https://github.com/davidpatrick))
- Add login_hint to permitted params [\#123](https://github.com/auth0/omniauth-auth0/pull/123) ([Roriz](https://github.com/Roriz))

## [v2.5.0](https://github.com/auth0/omniauth-auth0/tree/v2.5.0) (2021-01-21)

[Full Changelog](https://github.com/auth0/omniauth-auth0/compare/v2.4.2...v2.5.0)

**Added**

- Parsing claims from the id_token [\#120](https://github.com/auth0/omniauth-auth0/pull/120) ([davidpatrick](https://github.com/davidpatrick))

**Changed**

- Setup build matrix in CI [\#116](https://github.com/auth0/omniauth-auth0/pull/116) ([dmathieu](https://github.com/dmathieu))

**Fixed**

- Fixes params passed to authorize [\#119](https://github.com/auth0/omniauth-auth0/pull/119) ([davidpatrick](https://github.com/davidpatrick))

## [v2.4.2](https://github.com/auth0/omniauth-auth0/tree/v2.4.2) (2021-01-19)

[Full Changelog](https://github.com/auth0/omniauth-auth0/compare/v2.4.1...v2.4.2)

**Fixed**

- Lock Omniauth to 1.9 in gemspec

## [v2.4.1](https://github.com/auth0/omniauth-auth0/tree/v2.4.1) (2020-10-08)

[Full Changelog](https://github.com/auth0/omniauth-auth0/compare/v2.4.0...v2.4.1)

**Fixed**

- Verify the JWT Signature [\#109](https://github.com/auth0/omniauth-auth0/pull/109) ([jimmyjames](https://github.com/jimmyjames))

## [v2.4.0](https://github.com/auth0/omniauth-auth0/tree/v2.4.0) (2020-09-22)

[Full Changelog](https://github.com/auth0/omniauth-auth0/compare/v2.3.1...v2.4.0)

**Security**

- Bump rack from 2.2.2 to 2.2.3 [\#107](https://github.com/auth0/omniauth-auth0/pull/107) ([dependabot](https://github.com/dependabot))
- Update dependencies [\#100](https://github.com/auth0/omniauth-auth0/pull/100) ([Albalmaceda](https://github.com/Albalmaceda))

**Added**

- Add support for screen_hint=signup param [\#103](https://github.com/auth0/omniauth-auth0/pull/103) ([bbean86](https://github.com/bbean86))
- Add support for `connection_scope` in params [\#99](https://github.com/auth0/omniauth-auth0/pull/99) ([felixclack](https://github.com/felixclack))

## [v2.3.1](https://github.com/auth0/omniauth-auth0/tree/v2.3.1) (2020-03-27)

[Full Changelog](https://github.com/auth0/omniauth-auth0/compare/v2.3.0...v2.3.1)

**Fixed bugs:**

- Fixes dependency issue [\#97](https://github.com/auth0/omniauth-auth0/pull/97) ([davidpatrick](https://github.com/davidpatrick))
- Fix "NameError: uninitialized constant OmniAuth::Auth0::TokenValidationError" [\#96](https://github.com/auth0/omniauth-auth0/pull/96) ([stefanwork](https://github.com/stefanwork))

## [v2.3.0](https://github.com/auth0/omniauth-auth0/tree/v2.3.0) (2020-03-06)

[Full Changelog](https://github.com/auth0/omniauth-auth0/compare/v2.2.0...v2.3.0)

**Added**

- Improved OIDC Compliance [\#92](https://github.com/auth0/omniauth-auth0/pull/92) ([davidpatrick](https://github.com/davidpatrick))

## [v2.2.0](https://github.com/auth0/omniauth-auth0/tree/v2.2.0) (2018-04-18)

[Full Changelog](https://github.com/auth0/omniauth-auth0/compare/v2.1.0...v2.2.0)

**Closed issues**

- It supports custom domain? [\#71](https://github.com/auth0/omniauth-auth0/issues/71)
- Valid Login, No Details: email=nil image=nil name="github|38257089" nickname=nil [\#70](https://github.com/auth0/omniauth-auth0/issues/70)

**Added**

- Custom issuer [\#77](https://github.com/auth0/omniauth-auth0/pull/77) ([ryan-rosenfeld](https://github.com/ryan-rosenfeld))
- Add telemetry to token endpoint [\#74](https://github.com/auth0/omniauth-auth0/pull/74) ([joshcanhelp](https://github.com/joshcanhelp))

**Changed**

- Remove telemetry from authorize URL [\#75](https://github.com/auth0/omniauth-auth0/pull/75) ([joshcanhelp](https://github.com/joshcanhelp))

## [v2.1.0](https://github.com/auth0/omniauth-auth0/tree/v2.1.0) (2018-10-30)

[Full Changelog](https://github.com/auth0/omniauth-auth0/compare/v2.0.0...v2.1.0)

**Closed issues**

- URL should be spelled uppercase outside of code [\#64](https://github.com/auth0/omniauth-auth0/issues/64)
- Add prompt=none authorization param handler [\#58](https://github.com/auth0/omniauth-auth0/issues/58)
- Could not find a valid mapping for path "/auth/oauth2/callback" [\#56](https://github.com/auth0/omniauth-auth0/issues/56)
- I had to downgrade my gems to use this strategy :-( [\#53](https://github.com/auth0/omniauth-auth0/issues/53)
- CSRF detected [\#49](https://github.com/auth0/omniauth-auth0/issues/49)
- /auth/:provider route not registered? [\#47](https://github.com/auth0/omniauth-auth0/issues/47)

**Added**

- Add ID token validation [\#62](https://github.com/auth0/omniauth-auth0/pull/62) ([joshcanhelp](https://github.com/joshcanhelp))
- Silent authentication [\#59](https://github.com/auth0/omniauth-auth0/pull/59) ([batalla3692](https://github.com/batalla3692))
- Pass connection parameter to auth0 [\#54](https://github.com/auth0/omniauth-auth0/pull/54) ([tomgi](https://github.com/tomgi))

**Changed**

- Update to omniauth-oauth2 [\#55](https://github.com/auth0/omniauth-auth0/pull/55) ([chills42](https://github.com/chills42))

**Fixed**

- Fix Rubocop errors [\#66](https://github.com/auth0/omniauth-auth0/pull/66) ([joshcanhelp](https://github.com/joshcanhelp))
- Fix minute bug in README.md [\#63](https://github.com/auth0/omniauth-auth0/pull/63) ([rahuldess](https://github.com/rahuldess))

## [v2.0.0](https://github.com/auth0/omniauth-auth0/tree/v2.0.0) (2017-01-25)

[Full Changelog](https://github.com/auth0/omniauth-auth0/compare/v1.4.1...v2.0.0)

Updated library to handle OIDC conformant clients and OAuth2 features in Auth0.
This affects how the `credentials` and `info` attributes are populated since the payload of /oauth/token and /userinfo are different when using OAuth2/OIDC features.

The `credentials` hash will always have an `access_token` and might have a `refresh_token` (if it's allowed in your API settings in Auth0 dashboard and requested using `offline_access` scope) and an `id_token` (scope `openid` is needed for Auth0 to return it).

The `info` object will use the [OmniAuth schema](https://github.com/omniauth/omniauth/wiki/Auth-Hash-Schema#schema-10-and-later) after calling /userinfo:

- name: `name` attribute in userinfo response or `sub` if not available.
- email: `email` attribute in userinfo response.
- nickname: `nickname` attribute in userinfo response.
- image: `picture` attribute in userinfo response.

Also in `extra` will have in `raw_info` the full /userinfo response.

**Fixed**

- Use image attribute of omniauth instead of picture [\#45](https://github.com/auth0/omniauth-auth0/pull/45) ([hzalaz](https://github.com/hzalaz))
- Rework strategy to handle OAuth and OIDC [\#44](https://github.com/auth0/omniauth-auth0/pull/44) ([hzalaz](https://github.com/hzalaz))
- lock v10 update, dependencies update [\#41](https://github.com/auth0/omniauth-auth0/pull/41) ([Amialc](https://github.com/Amialc))

## [v1.4.2](https://github.com/auth0/omniauth-auth0/tree/v1.4.2) (2016-06-13)

[Full Changelog](https://github.com/auth0/omniauth-auth0/compare/v1.4.1...v1.4.2)

**Added**

- Link to OmniAuth site [\#36](https://github.com/auth0/omniauth-auth0/pull/36) ([jghaines](https://github.com/jghaines))
- add ssl fix to RoR example [\#31](https://github.com/auth0/omniauth-auth0/pull/31) ([Amialc](https://github.com/Amialc))
- Update LICENSE [\#17](https://github.com/auth0/omniauth-auth0/pull/17) ([aguerere](https://github.com/aguerere))

**Changed**

- Update lock to version 9 [\#34](https://github.com/auth0/omniauth-auth0/pull/34) ([Annyv2](https://github.com/Annyv2))
- Update Gemfile [\#22](https://github.com/auth0/omniauth-auth0/pull/22) ([Annyv2](https://github.com/Annyv2))
- Update lock [\#15](https://github.com/auth0/omniauth-auth0/pull/15) ([Annyv2](https://github.com/Annyv2))

**Fixed**

- Fix setup [\#38](https://github.com/auth0/omniauth-auth0/pull/38) ([deepak](https://github.com/deepak))
- Added missing instruction [\#30](https://github.com/auth0/omniauth-auth0/pull/30) ([Annyv2](https://github.com/Annyv2))
- Fixes undefined Auth0Lock issue [\#28](https://github.com/auth0/omniauth-auth0/pull/28) ([Annyv2](https://github.com/Annyv2))
- Update Readme [\#27](https://github.com/auth0/omniauth-auth0/pull/27) ([Annyv2](https://github.com/Annyv2))

## [v1.4.1](https://github.com/auth0/omniauth-auth0/tree/v1.4.1) (2015-11-18)

[Full Changelog](https://github.com/auth0/omniauth-auth0/compare/v1.4.0...v1.4.1)

**Merged pull requests:**

- Updating the strategy to set the refresh token in the credentials [\#14](https://github.com/auth0/omniauth-auth0/pull/14) ([LindseyB](https://github.com/LindseyB))
- Update README.md [\#13](https://github.com/auth0/omniauth-auth0/pull/13) ([Annyv2](https://github.com/Annyv2))
- Update home.js [\#12](https://github.com/auth0/omniauth-auth0/pull/12) ([Annyv2](https://github.com/Annyv2))
- Add nested module in version.rb [\#9](https://github.com/auth0/omniauth-auth0/pull/9) ([l4u](https://github.com/l4u))

## [v1.4.0](https://github.com/auth0/omniauth-auth0/tree/v1.4.0) (2015-06-01)

**Merged pull requests:**

- Client headers [\#8](https://github.com/auth0/omniauth-auth0/pull/8) ([benschwarz](https://github.com/benschwarz))
- Web application seed with Lock [\#5](https://github.com/auth0/omniauth-auth0/pull/5) ([sandrinodimattia](https://github.com/sandrinodimattia))
- Create LICENSE.md [\#4](https://github.com/auth0/omniauth-auth0/pull/4) ([pose](https://github.com/pose))
- Update README.md [\#3](https://github.com/auth0/omniauth-auth0/pull/3) ([pose](https://github.com/pose))
- Fix Markdown typo [\#2](https://github.com/auth0/omniauth-auth0/pull/2) ([dentarg](https://github.com/dentarg))

\* _This Change Log was automatically generated by [github_changelog_generator](https://github.com/skywinder/Github-Changelog-Generator)_
