**v1.1.4**
- Aligned the menu icons and naming with TecLib's Oauth SSO Applications plugin in `src/Config.php`
- Altered `name` in `setup.php:122` to reflect plugin name correctly with value `Glpisaml`
- Altered `homepage` in `setup.php:125` to reflect correct GIT repository at `Codeberg.org`
- Altered menu name `src/RuleSaml.php` method `getTitle()` return value to  `JIT import rules`.
- Altered menu name `src/RuleSamlCollection.php` method `getTitle()` return value to `Jit import rules` 
- Altered JIT button name in `src/Config.php:142` to match the RuleCollection menu name `Jit import rules` 
- Added additional validation and warning to check if the example certificate `withlove.from.donuts.nl` is used in the configuration in `src/config/ConfigItem.php:599`.

**v1.1.3**
- Added logic to store the initial sessionId for reference in state table.
- Altered error messages in `/front/meta.php` to be more generic less helpfull for added security
- Added method `getConfigIdByEmailDomain` to `src/config.php` to get IDP ID based on given CONF_DOMAIN
- Added Method `getConfigDomain` to `src/configEntity.php` to fetch the CONF_DOMAIN from the fetched entity used
  to evaluate if the button for the entity needs to be shown.
- Extended `doAuth` in `src/LoginFlow.php` to also evaluate username field in login screen and match it
  with idp configured userdomain. This allows a user to simply 'provide' its username and press login triggering
  a saml request if the domain in the username matches a given idp's userdomain configuration.
- Updated the loginbutton logic to not show on the login page if there are no buttons to show.
- Added a test `popover` in the config screen with the `copy meta url button` to see if that cleans 
  the configuration further and how that would look and feel. Considering to leave it and see if 
  and how ppl respond to it.
- Added logic to `generateForm` in `src\Config\ConfigForm.php` to detect if the login button will be hidden
- Added errorhelpers to `templates/configForm.html.twig` to warn users the login button will be hidden.
- Added errorhelpers to `templates/configForm.html.twig` to explain userdomain behaviour if configured.
- Fixed issue https://codeberg.org/QuinQuies/glpisaml/issues/20
- Added saml cookies to help plugin correctly track session on redirect with session.cookie_samesite = strict.
- Added additional logic to `src/loginState.php` hardening the logic
- Added meta redirect to deal with session.cookie_samesite = strict after Saml Redirect back to GLPI
- Added additional explanaitions to config item in `src/Config/ConfigItem.php`
- Fixed issue https://codeberg.org/QuinQuies/glpisaml/issues/30
- Added `is_deleted = 0` filter in `src/Config.php` method `getLoginButtons`
- Fixed issue https://codeberg.org/QuinQuies/glpisaml/issues/31
- Implemented https://codeberg.org/QuinQuies/glpisaml/issues/14
- Added additional validations on certificate validation method in `src/Config/ConfigItem.php` method `parseX509Certificate` 
