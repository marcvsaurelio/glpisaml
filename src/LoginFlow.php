<?php
/**
 *  ------------------------------------------------------------------------
 *  GLPISaml
 *
 *  GLPISaml was inspired by the initial work of Derrick Smith's
 *  PhpSaml. This project's intend is to address some structural issues
 *  caused by the gradual development of GLPI and the broad amount of
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
 *  @version    1.1.3
 *  @author     Chris Gralike
 *  @copyright  Copyright (c) 2024 by Chris Gralike
 *  @license    GPLv3+
 *  @see        https://github.com/DonutsNL/GLPISaml/readme.md
 *  @link       https://github.com/DonutsNL/GLPISaml
 * ------------------------------------------------------------------------
 *
 * The concern this class addresses is added because we want to add support
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
use Glpi\Application\View\TemplateRenderer;
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
                                                            // userData array added by SAML to response.
    public const POSTFIELD                   = 'samlIdpId';                                                             // https://codeberg.org/QuinQuies/glpisaml/issues/37

    // LOGIN FLOW AFTER PRESSING A IDP BUTTON.

    /**
     * Evaluates the session and determines if login/logout is required
     * Called by post_init hook via function in hooks.php. It watches POST
     * information passed from the loginForm.
     *
     * @return  boolean
     * @since                   1.0.0
     */
    public function doAuth(): bool
    {
        // global $GLPI_CACHE;
        // Get current state
        if(!$state = new Loginstate()){
            $this->printError(__('Could not load loginState', PLUGIN_NAME));
        }else{
            // Evaluate database state, do we need to force logoff a user,
            // but only after user has been logged in.

            // Do we need to skip because of exclusion?
            if($state->isExcluded()){
                return $state->getExcludeAction();
            }
        }

        // Check if the logout button was pressed and handle request!
        // https://codeberg.org/QuinQuies/glpisaml/issues/18
        if ( isset($_SERVER['REQUEST_URI']) && ( strpos($_SERVER['REQUEST_URI'], 'front/logout.php') !== false) ){
            // Stop GLPI from processing cookie based auto login.
            $_SESSION['noAUTO'] = 1;
            $this->performLogOff();
        }

        // https://codeberg.org/QuinQuies/glpisaml/issues/3
        // Capture the post of regular login and verify if the provided domain is SSO enabled.
        // by evaluating the domain portion against the configured user domains.
        // we need to iterate through the keys because of the added csrf token i.e.
        // [fielda[csrf_token]] = value.
        foreach($_POST as $key => $value){
            if(strstr($key, 'fielda')                               &&    // Test keys if fielda[token] is present in the POST.
               !empty($_POST[$key])                                 &&    // Test if fielda actually has a value we can process
               $id = Config::getConfigIdByEmailDomain($_POST[$key]) ){    // If all is true try to find an matching idp id.
                    $_POST[self::POSTFIELD] = $id;                        // If we found an ID Set the POST phpsaml to our found ID this will trigger
            }
        }

        // Check if a SAML button was pressed and handle the corresponding logon request!
        if (isset($_POST[self::POSTFIELD])         &&      // Must be set
            is_numeric($_POST[self::POSTFIELD])    &&      // Value must be numeric
            strlen($_POST[self::POSTFIELD]) < 3    ){      // Should not exceed 999

            // If we know the idp we register it in the login State
            $state->setIdpId(filter_var($_POST[self::POSTFIELD], FILTER_SANITIZE_NUMBER_INT));

            // Update the current phase in database. The state is verified by the Acs
            // while handling the received SamlResponse. Any other state will force Acs
            // into an error state. This is to prevent unexpected (possibly replayed)
            // samlResponses from being processed. to prevent playback attacks.
            if(!$state->setPhase(LoginState::PHASE_SAML_ACS) ){
                $this->printError(__('Could not update the loginState and therefor stopped the loginFlow', PLUGIN_NAME));
            }

            // Actually perform SSO
            $this->performSamlSSO($state);
        }
        // else
        return false;
    }

    /**
     * Method uses phpSaml to perform a sign-in request with the
     * selected Idp that is stored in the state. The Idp will
     * perform the sign-in and if successful perform a user redirect
     * to /marketplace/glpisaml/front/acs.php
     *
     * @param   Loginstate $state       The current LoginState
     * @return  void
     * @since                           1.0.0
     */
    protected function performSamlSSO(Loginstate $state): void
    {
        global $CFG_GLPI;
        
        // Fetch the correct configEntity GLPI
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
        $userFields = User::getUserInputFieldsFromSamlClaim($response);

        // Try to populate GLPI Auth using provided attributes;
        try {
            $auth = (new GlpiAuth())->loadUser($userFields);
        } catch (Throwable $e) {
            $this->printError($e->getMessage(), 'doSamlLogin');
        }

        // Populate Glpi session with Auth.
        Session::init($auth);

        // Update the current state
        if(!$state = new Loginstate()){ $this->printError(__('Could not load loginState from database!', PLUGIN_NAME)); }
        $state->setPhase(LoginState::PHASE_GLPI_AUTH);

        // Redirect back to main page
        // We should fix added .'/' to prevent (string|int) type issue.
        // Html::redirect($CFG_GLPI['url_base']);
        // https://codeberg.org/QuinQuies/glpisaml/issues/42
        $this->doMetaRefresh($CFG_GLPI['url_base'].'/');
    }

    /**
     * This is a 'nasty' hack to deal with the session cookie not being accessible on
     * redirect with the php.ini:session.cookie_samesite='Strict'. Performing a meta
     * refresh makes sure the cookie survives.
     *
     * @param    Response  Response object with the samlResponse attributes.
     * @return   array     user->add input fields array with properties.
     * @since    1.1.3
     */
    private function doMetaRefresh(string $location): void
    {
        $location = (filter_var($location, FILTER_VALIDATE_URL)) ? $location : '/';
        echo <<<HTML
        <html>
        <head>
            <meta http-equiv="refresh" content="0;URL='$location'"/>
        </head>
            <body></body>
        </html>
        HTML;
        exit;
    }

    /**
     * Responsible to generate the login buttons to show in conjunction
     * with the glpi login field (not enforced). Only shows if there are
     * buttons to show. Else it will skip.
     *
     * @see https://github.com/DonutsNL/glpisaml/issues/7
     * @return  string  html form for the login screen
     * @since           1.0.0
     */
    public function showLoginScreen(): void
    {
        // Fetch the global DB object;
        $tplVars = Config::getLoginButtons(12);
        // Only show the interface if we have buttons to show.
        if(!empty($tplVars)){
            // Define static translatable elements
            $tplVars['action']     = Plugin::getWebDir(PLUGIN_NAME, true);
            $tplVars['header']     = __('Login with external provider', PLUGIN_NAME);
            $tplVars['noconfig']   = __('No SSO buttons enabled yet. Try your SSO username instead.', PLUGIN_NAME);
            $tplVars['postfield']   = self::POSTFIELD;

            // https://codeberg.org/QuinQuies/glpisaml/issues/12
            TemplateRenderer::getInstance()->display('@glpisaml/loginScreen.html.twig',  $tplVars);
        }
    }

    // LOGOUT
    /**
     * Makes sure user is logged out of GLPI, if required logged out from SAML.
     * @return void
     */
    protected function performLogOff(): void
    {
        // Update the loginState
        if(!$state = new Loginstate()){ $this->printError(__('Could not load loginState from database!', PLUGIN_NAME)); }
        $state->setPhase(LoginState::PHASE_LOGOFF);

        // Invalidate GLPI session (needs review)
        $validId   = @$_SESSION['valid_id'];
        $cookieKey = array_search($validId, $_COOKIE);
        Session::destroy();
        
        //Remove cookie?
        $cookiePath = ini_get('session.cookie_path');
        if (isset($_COOKIE[$cookieKey])) {
           setcookie($cookieKey, '', time() - 3600, $cookiePath);
           unset($_COOKIE[$cookieKey]);
        }

        // If required perform IDP logout as well
        // Future feature.
        // https://codeberg.org/QuinQuies/glpisaml/issues/1
    }

    // ERROR HANDLING

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
        $tplVars['header']      = __('⚠️ we are unable to log you in', PLUGIN_NAME);
        $tplVars['error']       = htmlentities($errorMsg);
        $tplVars['returnPath']  = $CFG_GLPI["root_doc"] .'/';
        $tplVars['returnLabel'] = __('Return to GLPI', PLUGIN_NAME);
        // print header
        Html::nullHeader("Login",  $CFG_GLPI["root_doc"] . '/');
        // Render twig template
        // https://codeberg.org/QuinQuies/glpisaml/issues/12
        echo TemplateRenderer::getInstance()->render('@glpisaml/loginError.html.twig',  $tplVars);
        // print footer
        Html::nullFooter();
        // This function always needs to exit to prevent accidental
        // login with disabled or deleted users!
        exit;
    }

   
    /**
     * Prints a nice error message with 'back' button and
     * logs the error passed in the GlpiSaml log file.
     *
     * @see https://github.com/DonutsNL/glpisaml/issues/7
     * @param string errorMsg   string with raw error message to be printed
     * @param string action     optionally add 'action' that was performed to error message
     * @param string extended   optionally add 'extended' information about the error in the log file.
     * @return void             no return, PHP execution is terminated by this method.
     * @since 1.0.0
     */
    public static function printError(string $errorMsg, string $action = '', string $extended = ''): void
    {
        // Pull GLPI config into scope.
        global $CFG_GLPI;

        // Log in file
        Toolbox::logInFile(PLUGIN_NAME."-errors", $errorMsg . "\n", true);
        if($extended){
            Toolbox::logInFile(PLUGIN_NAME."-errors", $extended . "\n", true);
        }

        // Define static translatable elements
        $tplVars['header']      = __('⚠️ An error occurred', PLUGIN_NAME);
        $tplVars['leading']     = __("We are sorry, something went terribly wrong while processing your $action request!", PLUGIN_NAME);
        $tplVars['error']       = $errorMsg;
        $tplVars['returnPath']  = $CFG_GLPI["root_doc"] .'/';
        $tplVars['returnLabel'] = __('Return to GLPI', PLUGIN_NAME);
        // print header
        Html::nullHeader("Login",  $CFG_GLPI["root_doc"] . '/');
        // Render twig template
        echo TemplateRenderer::getInstance()->render('@glpisaml/errorScreen.html.twig',  $tplVars);
        // print footer
        Html::nullFooter();
        
        // make sure we stop execution.
        exit;
    }

}
