<?php
/**
 *  ------------------------------------------------------------------------
 *  GLPISaml
 *
 *  GLPISaml was inspired by the initial work of Derrick Smith's
 *  PhpSaml. This project's intend is to address some structural issues
 *  caused by the gradual development of GLPI and the broad ammount of
 *  wishes expressed by the community.
 *
 *  Copyright (C) 2024 by Chris Gralike
 *  ------------------------------------------------------------------------
 *
 * LICENSE
 *
 * This file is part of GLPISaml project.
 *
 * GLPISaml plugin is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GLPISaml is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with GLPISaml. If not, see <http://www.gnu.org/licenses/> or
 * https://choosealicense.com/licenses/gpl-3.0/
 *
 * ------------------------------------------------------------------------
 *
 *  @package    GLPISaml
 *  @version    1.1.1
 *  @author     Chris Gralike
 *  @copyright  Copyright (c) 2024 by Chris Gralike
 *  @license    GPLv3+
 *  @see        https://github.com/DonutsNL/GLPISaml/readme.md
 *  @link       https://github.com/DonutsNL/GLPISaml
 * ------------------------------------------------------------------------
 *
 * The concern this class adresses is added because we want to add support
 * for multiple idp's. Deciding what idp to use might involve more complex
 * algorithms then we used (1:1) in the previous version of phpSaml. These
 * can then be implemented here.
 *
 **/

namespace GlpiPlugin\Glpisaml;

use Html;
use Plugin;
use Session;
use Toolbox;
use Throwable;
use OneLogin\Saml2\Auth as samlAuth;
use OneLogin\Saml2\Response;
use GlpiPlugin\Glpisaml\Config;
use GlpiPlugin\Glpisaml\LoginState;
use GlpiPlugin\Glpisaml\Config\ConfigEntity;
use GlpiPlugin\Glpisaml\LoginFlow\User;
use GlpiPlugin\Glpisaml\LoginFlow\Auth as glpiAuth;


/**
 * This object brings it all together. It is responsible to handle the
 * main logic concerned with the Saml login and logout flows.
 * it will call upon various supporting objects to perform its tasks.
 */
class LoginFlow
{
    /**
     * Where to find the loginScreen template.
     * @since 1.0.0
     */
    public const HTML_TEMPLATE_FILE = PLUGIN_GLPISAML_TPLDIR.'/loginScreen.html';

    /**
     * samlResponse attributes or claims provided by IdP.
     * @see https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
     * @see https://learn.microsoft.com/en-us/entra/identity-platform/reference-saml-tokens
     */
    public const SCHEMA_NAMEID               = 'NameId';                                                                // Used as primairy if it contains valid email.
    public const SCHEMA_NAME                 = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name';            // Entra claim not used
    public const SCHEMA_SURNAME              = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname';         // Used in user creation JIT - Optional
    public const SCHEMA_FIRSTNAME            = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/firstname';       // Used in user creation JIT - Optional
    public const SCHEMA_GIVENNAME            = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname';       // Used in user creation JIT - Optional
    public const SCHEMA_EMAILADDRESS         = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress';    // Used as Fallback in  JIT for missing email in NameId.
    public const SCHEMA_TENANTID             = 'http://schemas.microsoft.com/identity/claims/tenantid';                 // Entra claim not used
    public const SCHEMA_OBJECTID             = 'http://schemas.microsoft.com/identity/claims/objectidentifier';         // Entra claim not used
    public const SCHEMA_DISPLAYNAME          = 'http://schemas.microsoft.com/identity/claims/displayname';              // Entra claim not used
    public const SCHEMA_IDP                  = 'http://schemas.microsoft.com/identity/claims/identityprovider';         // Entra claim not used
    public const SCHEMA_AUTHMETHODSREF       = 'http://schemas.microsoft.com/claims/authnmethodsreferences';            // Entra claim not used
    public const USERDATA                    = 'userData';                                                              // userData array added by PHPSAML to response.

    // LOGIN FLOW AFTER PRESSING A IDP BUTTON.

    /**
     * Evaluates the session and determins if login/logout is required
     * Called by post_init hook via function in hooks.php. It watches POST
     * information passed from the loginForm.
     *
     * @return  boolean
     * @since                   1.0.0
     */
    public function doAuth(): bool
    {
        global $GLPI_CACHE;
        // Get current state
        if(!$state = new Loginstate()){
            $this->printError(__('Could not load loginState from database!', PLUGIN_NAME));
        }

        // Check if the logout button was pressed and handle request!
        if (strpos($_SERVER['REQUEST_URI'], 'front/logout.php') !== false) {
            // Stop GLPI from processing cookiebased autologin.
            $_SESSION['noAUTO'] = 1;
            $this->performSamlLogOff();
            $this->performGlpiLogOff();
        }

        // Evaluate database state, do we need to force logoff a user,
        // but only after user has been logged in.

        // Capture the post of regular login and verify if the domain is SSO enabled.
        // https://codeberg.org/QuinQuies/glpisaml/issues/3
        foreach($_POST as $key => $value){
            if(strstr($key, 'fielda')){
                // TODO validate domain and perform SSO if matched.
            }
        }

        // Check if a SAML button was pressed and handle the corresponding logon request!
        if (isset($_POST['phpsaml'])         &&      // Must be set
            is_numeric($_POST['phpsaml'])    &&      // Value must be numeric
            strlen($_POST['phpsaml']) < 3    ){      // Should not exceed 999

            // If we know the idp we register it in the login State
            $state->setIdpId(filter_var($_POST['phpsaml'], FILTER_SANITIZE_NUMBER_INT));

            // Set the idpId in php session because its lost after login due to
            // sessionId reset.
            $GLPI_CACHE->set(LoginState::IDP_ID, filter_var($_POST['phpsaml'], FILTER_SANITIZE_NUMBER_INT));
            
            // Update the current phase in database. The state is verified by the Acs
            // while handling the received SamlResponse. Any other state will force Acs
            // into an error state. This is to prevent unexpected (possibly replayed)
            // samlResponses from being processed. to prevent playback attacks.
            $state->setPhase(LoginState::PHASE_SAML_ACS);

            // Actually perform SSO
            $this->performSamlSSO($state);
        }

        // else
        return false;
    }

    /**
     * Method uses phpSaml to perform a signin request with the
     * selected Idp that is stored in the state. The Idp will
     * perform the signin and if succesfull perform a user redirect
     * to /marketplace/glpisaml/front/acs.php
     *
     * @param   Loginstate $state       The current LoginState
     * @return  void
     * @since                           1.0.0
     */
    protected function performSamlSSO(Loginstate $state): void
    {
        global $CFG_GLPI;
        
        // Fetch the correct configEntity
        if($configEntity = new ConfigEntity($state->getIdpId())){
            $samlConfig = $configEntity->getPhpSamlConfig();
        }

        // Validate if the IDP configuration is enabled
        // https://codeberg.org/QuinQuies/glpisaml/issues/4
        if($configEntity->isActive()){
            // Initialize the OneLogin phpSaml auth object
            // using the requested phpSaml configuration from
            // the glpisaml config database. Catch all throwable errors
            // and exceptions.
            try { $auth = new samlAuth($samlConfig); } catch (Throwable $e) {
                $this->printError($e->getMessage(), 'Saml::Auth->init', var_export($auth->getErrors(), true));
            }
            
            // Perform a login request with the loaded glpiSaml
            // configuration. Catch all throwable errors and exceptions
            try { $auth->login($CFG_GLPI["url_base"]); } catch (Throwable $e) {
                $this->printError($e->getMessage(), 'Saml::Auth->login', var_export($auth->getErrors(), true));
            }
        } // Do nothing, ignore the samlSSORequest.
    }

    /**
     * Called by the src/LoginFlow/Acs class if the received response was valid
     * to handle the samlLogin or invalidate the login if there are deeper issues
     * with the response, for instance important claims are missing.
     *
     * @param   Response    SamlResponse from Acs.
     * @return  void
     * @since               1.0.0
     */
    protected function performSamlLogin(Response $response): void
    {
        global $CFG_GLPI;

        // Validate samlResponse and returns provided Saml attributes (claims).
        // validation will print and exit on errors because user information is required.
        $userFields = $this->getUserInputFieldsFromSamlClaim($response);

        // Try to populate GLPI Auth using provided attributes;
        try {
            $auth = (new GlpiAuth())->loadUser($userFields);
        } catch (Throwable $e) {
            $this->printError($e->getMessage(), 'doSamlLogin');
        }

        // Update the current state
        if(!$state = new Loginstate()){ $this->printError(__('Could not load loginState from database!', PLUGIN_NAME)); }
        $state->setPhase(LoginState::PHASE_SAML_AUTH);

        // Populate Glpi session with Auth.
        Session::init($auth);

        // Redirect back to mainpage
        Html::redirect($CFG_GLPI['url_base'].'/');
    }

    /**
     * This function figures out what the samlResponse provided claims are and
     * how to best populate the GLPI userObject or triggers an error if
     * essential claims are missing from the samlResponse body.
     * Maybe move this method to the userObject in the future.
     *
     * @param    Response  Response object with the samlRespons attributes.
     * @return   array     user->add input fields array with properties.
     */
     public function getUserInputFieldsFromSamlClaim(Response $response): array     //NOSONAR - Complexity by design.
     {
        // Validate nameId clain from provided samlResponse.
        // These claims sometimes need to be configured manually
        // at the Identity provider. NameId is required and should be
        // formatted as an valid email. Others properties are nice to
        // have and will make the user properties more complete.
        if(!$user[User::NAME] = $response->getNameId()) {
            $this->printError(__('NameId attribute is missing in samlResponse', PLUGIN_NAME),
                              'getUserInputFieldsFromSamlClaim',
                              var_export($response, true));
        }
           
        // Get additional claims from the samlResponse.
        if(!$claims[LoginFlow::USERDATA] = $response->getAttributes()) {
            $claims = '';
        }

        // If the string #EXT# if found, a guest account is used thats not
        // transformed properly by entra. In this case write an error and exit!
        // https://github.com/derricksmith/phpsaml/issues/135
        if(strstr($user[User::NAME], '#EXT#@')){
            $this->printError(__('Detected a default guest user in samlResponse, make sure nameid,
                                name are populated using user.mail instead of the uset.principalname.<br>
                                You can use the debug saml dumps to validate and compare the claims passed.<br>
                                They should contain the original email addresses.<br>
                                Also see: https://learn.microsoft.com/en-us/azure/active-directory/develop/saml-claims-customization', PLUGIN_NAME),
                                'getUserInputFieldsFromSamlClaim',
                                var_export($response, true));
        }

        // Figure out what username to set.
        // Can we use the NameId as username
        if(!filter_var($user[User::NAME], FILTER_VALIDATE_EMAIL)){
            // See if we can fall back using the email address in the claim (if any).
            if(isset($claims[LoginFlow::USERDATA][LoginFlow::SCHEMA_EMAILADDRESS])) {
                // Validate the emailadress in the claim. If its valid we continue processing it.
                if(!filter_var($claims[LoginFlow::USERDATA][LoginFlow::SCHEMA_EMAILADDRESS], FILTER_VALIDATE_EMAIL)){
                    $this->printError(__('SamlResponse should have at least 1 valid emailaddress for GLPI  to find
                                          the corresponding GLPI user or create it (with JIT enabled). For this purpose make
                                          sure either the IDP provided NameId property is populated with the emailaddress format,
                                          or configure the IDP to add the users emailaddress in the samlResponse claims using
                                          the designated schema property key:'.self::SCHEMA_EMAILADDRESS.' = "valid@userEmail.Address".', PLUGIN_NAME),
                                         'getUserInputFieldsFromSamlClaim',
                                          var_export($response, true));
                }
                // Set the emailaddress claim as the username and email.
                $user[User::NAME]   = $claims[LoginFlow::USERDATA][LoginFlow::SCHEMA_EMAILADDRESS][0];
                $user[User::EMAIL]  = [$claims[LoginFlow::USERDATA][LoginFlow::SCHEMA_EMAILADDRESS][0]];
            }else{
                // No emailaddress found in the samlResponse.
                // We need at least one valid emailaddress from the NameId or a emailaddress claim.
                // to search for a user or create one via JIT.
                $this->printError(__('SamlResponse should have at least 1 valid emailaddress for GLPI  to find
                                      the corresponding GLPI user or create it (with JIT enabled). For this purpose make
                                      sure either the IDP provided NameId property is populated with the emailaddress format,
                                      or configure the IDP to add the users emailaddress in the samlResponse claims using
                                      the designated schema property key:'.self::SCHEMA_EMAILADDRESS.' = "valid@userEmail.Address".', PLUGIN_NAME),
                                     'getUserInputFieldsFromSamlClaim',
                                      var_export($response, true));
            }
        }else{
            // The NameId property can be used for the username and emailaddress.
            // because $user[User::NAME] is allready set and contains a valid emailaddress.
            // This means we can focus on the email claim.
            // First check if an additional email claim was provided.
            if(isset($claims[LoginFlow::USERDATA][LoginFlow::SCHEMA_EMAILADDRESS][0])){
                // If the provided emailaddress is different from the NameId then use the
                // additionally provided emailaddress as primairy emailaddress.
                if($claims[LoginFlow::USERDATA][LoginFlow::SCHEMA_EMAILADDRESS][0] != $user[User::NAME]){
                    // Validate it is a valid emailaddress
                    if(filter_var($claims[LoginFlow::USERDATA][LoginFlow::SCHEMA_EMAILADDRESS], FILTER_VALIDATE_EMAIL)){
                        $user[User::EMAIL] = [$claims[LoginFlow::USERDATA][LoginFlow::SCHEMA_EMAILADDRESS][0]];
                    }else{
                        //fall back to the provided NameId emailaddress
                        $user[User::EMAIL] = [$user[User::NAME]];
                    }
                // Fall back to the provided NameId emailaddress
                }else{
                    $user[User::EMAIL] = [$user[User::NAME]];
                }
            // Fall back to the provided NameId emailaddress
            }else{
                $user[User::EMAIL] = [$user[User::NAME]];
            }
        }

        // Do we have a valid firstname in the claim fields?
        // This field is optional, nice to have.
        if(isset($claims[LoginFlow::USERDATA][LoginFlow::SCHEMA_FIRSTNAME][0]) ||
           isset($claims[LoginFlow::USERDATA][LoginFlow::SCHEMA_GIVENNAME][0]) ){
                $user[User::FIRSTNAME] = (isset($claims[LoginFlow::USERDATA][LoginFlow::SCHEMA_FIRSTNAME][0]))
                    ? $claims[LoginFlow::USERDATA][LoginFlow::SCHEMA_FIRSTNAME][0]
                    : $claims[LoginFlow::USERDATA][LoginFlow::SCHEMA_GIVENNAME][0];
        }else{
            // try a fallback for users not using the valid schema's but keywords
            if(isset($claims[LoginFlow::USERDATA]['firstname'][0]) ||
               isset($claims[LoginFlow::USERDATA]['givenname'][0]) ){
                $user[User::FIRSTNAME] = (isset($claims[LoginFlow::USERDATA]['firstname'][0]))
                    ? $claims[LoginFlow::USERDATA]['firstname'][0]
                    : $claims[LoginFlow::USERDATA]['givenname'][0];
            }
        }

        // Do we have a valid surname to provision.
        // This field is optional, nice to have.
        if(isset($claims[LoginFlow::USERDATA][LoginFlow::SCHEMA_SURNAME][0])){
            $user[User::REALNAME] = $claims[LoginFlow::USERDATA][LoginFlow::SCHEMA_SURNAME][0];
        }

        // Set additional userfields for user creation (if needed)
        // These fields are used for user->add($input);
        $user[User::COMMENT] = __('Created by phpSaml Just-In-Time user creation on:'.date('Y-M-D H:i:s'));
        $password = bin2hex(random_bytes(20));
        $user[User::PASSWORD]   = $password;
        $user[User::PASSWORDN]  = $password;

        // Return the userArray.
        return $user;
    }

    /**
     * Responsible to generate a login screen with Idp buttons
     * using available idp configurations.
     *
     * @see https://github.com/DonutsNL/glpisaml/issues/7
     * @return  string  html form for the login screen
     * @since           1.0.0
     */
    public function showLoginScreen(): void
    {
        // Fetch the global DB object;
        $tplvars = Config::getLoginButtons(12);

        // Define static translatable elements
        $tplvars['action']     = Plugin::getWebDir(PLUGIN_NAME, true);
        $tplvars['header']     = __('Login with external provider', PLUGIN_NAME);
        $tplvars['noconfig']   = __('No valid or enabled saml configuration found', PLUGIN_NAME);

        // Render twig template
        $loader = new \Twig\Loader\FilesystemLoader(PLUGIN_GLPISAML_TPLDIR);
        $twig = new \Twig\Environment($loader);
        $template = $twig->load('loginScreen.html.twig');
        echo $template->render($tplvars);
    }

    /**
     * Shows a login error with human readable message
     *
     * @see https://github.com/DonutsNL/glpisaml/issues/7
     * @param   string   error message to show
     * @since 1.0.0
     */
    public static function showLoginError($errorMsg): void
    {
        global $CFG_GLPI;
        // Define static translatable elements
        $tplvars['header']      = __('⚠️ we are unable to log you in', PLUGIN_NAME);
        $tplvars['error']       = htmlentities($errorMsg);
        $tplvars['returnPath']  = $CFG_GLPI["root_doc"] .'/';
        $tplvars['returnLabel'] = __('Return to GLPI', PLUGIN_NAME);
        // print header
        Html::nullHeader("Login",  $CFG_GLPI["root_doc"] . '/');
        // Render twig template
        $loader = new \Twig\Loader\FilesystemLoader(PLUGIN_GLPISAML_TPLDIR);
        $twig = new \Twig\Environment($loader);
        $template = $twig->load('loginError.html.twig');
        echo $template->render($tplvars);
        // print footer
        Html::nullFooter();
        // This function always needs to exit to prevent accidental
        // login with disabled or deleted users!
        exit;
    }



    // LOGOUT FLOW EITHER REQUESTED BY GLPI OR REQUESTED BY THE IDP (SLO) OR FORCED BY ADMIN

    /**
     * Makes sure user is logged out of GLPI
     * @return void
     */
    protected function performGlpiLogOff(): void
    {
        $validId   = @$_SESSION['valid_id'];
        $cookieKey = array_search($validId, $_COOKIE);
        
        Session::destroy();
        
        //Remove cookie to allow new login
        $cookiePath = ini_get('session.cookie_path');
        
        if (isset($_COOKIE[$cookieKey])) {
           setcookie($cookieKey, '', time() - 3600, $cookiePath);
           unset($_COOKIE[$cookieKey]);
        }
    }
    
     /**
     * Makes sure user is logged out of responsible IDP provider
     * @return void
     */
    protected function performSamlLogOff(): void
    {
        global $CFG_GLPI;
        if(!$state = new Loginstate()){ $this->printError(__('Could not load loginState from database!', PLUGIN_NAME)); }
        $state->setPhase(LoginState::PHASE_LOGOFF);
    }


    // ERROR HANDLING
   
    /**
     * Prints a nice error message with 'back' button and
     * logs the error passed in the GlpiSaml logfile.
     *
     * @see https://github.com/DonutsNL/glpisaml/issues/7
     * @param string errorMsg   string with raw error message to be printed
     * @param string action     optionally add 'action' that was performed to error message
     * @param string extended   optionally add 'extended' information about the error in the logfile.
     * @return void             no return, PHP execution is terminated by this method.
     * @since 1.0.0
     */
    public function printError(string $errorMsg, string $action = '', string $extended = ''): void
    {
        // Pull GLPI config into scope.
        global $CFG_GLPI;

        // Log in file
        Toolbox::logInFile(PLUGIN_NAME."-errors", $errorMsg . "\n", true);
        if($extended){
            Toolbox::logInFile(PLUGIN_NAME."-errors", $extended . "\n", true);
        }

        // Define static translatable elements
        $tplvars['header']      = __('⚠️ An error occured', PLUGIN_NAME);
        $tplvars['leading']     = __("We are sorry, something went terribly wrong while processing your $action request!", PLUGIN_NAME);
        $tplvars['error']       = $errorMsg;
        $tplvars['returnPath']  = $CFG_GLPI["root_doc"] .'/';
        $tplvars['returnLabel'] = __('Return to GLPI', PLUGIN_NAME);

        // print header
        Html::nullHeader("Login",  $CFG_GLPI["root_doc"] . '/');

        // Render twig template
        $loader = new \Twig\Loader\FilesystemLoader(PLUGIN_GLPISAML_TPLDIR);
        $twig = new \Twig\Environment($loader);
        $template = $twig->load('errorScreen.html.twig');
        echo $template->render($tplvars);

        // print footer
        Html::nullFooter();
        
        // stop execution.
        exit;
    }

}
