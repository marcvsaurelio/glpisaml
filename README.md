# glpi saml
This plugin is a full rewrite by Chris Gralike of Derrick Smith's initial phpSAML plugin for GLPI. This plugin is redesigned and rewritten to be compatible with GLPI10+, Support multiple saml idp's, implement user right rules and more. It allows you to configure everything from the GLPI UI and dont require coding skills. It uses GLPI core components where possible for maximum compatibility and maintainability. It implements composer for quick 3rd party library updates if security issue's requires it. It follows the PSR best-practices where possible.

Want to support my work?
- Star my repo and contribute to my stargazer achievement. 
- Want to do more, I just love coffee: https://www.buymeacoffee.com/donutsnl
- Consider to donate codeberg.org to keep the European open source movement going.

# Status
PRODUCTION RELEASE

# Current Focus
* Fix currently reported issues
* Remove version checking (covered by GLPI marketplace)
* splitting the config
* Adding support for additional protocols
* Adding support for additional rules
* Adding support for account sync

# Contribute, ideas and help?
Join my (and hopefully our in the future) discord at: https://discord.gg/KyMdkqJcGz
Have coding experience (or are learning to code) and want to add meaningfull changes and additions? First start from your own repository by forking this repository and then create pull requests. Deal with any feedback you receive and see your pullrequest being merged. If you have proven to be consistant, then request access to the repository as contributor and help me build a great tool for people to enjoy. Just want to share your idea, then please create an issue outlining the issue or your idea.

**Coding:**
- [Follow PSR where possible](https://www.php-fig.org/psr/)
- Use a decent IDE and consider using plugins like:
- Code lenses (intelephense);
- PSR4 compliant namespace resolver;
- Composer integration;
- Xdebug profiler;
- SonarLint;
- Twig language support;
- tip: devsense PHP All-in-one.

# Credits
Special credits go to:
- Derrick Smith (creating the initial version PHPSaml)
- Raul, @gambware for their support to the OSS community (& buying me coffee), cheers!
- @MikeDevresse for providing fixes to the codebase.
- @SpyK-01 for licensing and sharing the logo via https://elements.envato.com/letter-shield-gradient-colorful-logo-XZ7LYCM.

# Get an idea where im going with this:
https://github.com/DonutsNL/phpsaml2/wiki/Plugin-Logic-and-Structure-Scratchboard
