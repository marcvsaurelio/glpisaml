<?php
/**
 * ------------------------------------------------------------------------
 * GLPISaml
 *
 * GLPISaml is heavily influenced by the initial work of Derrick Smith's
 * PhpSaml. This project's intent is to address some structural issues and
 * changes made by the gradual development of GLPI and provide a free, safe
 * and functional way of implementing SAML authentication in GLPI.
 *
 * Copyright (C) 2024 by Chris Gralike
 * ------------------------------------------------------------------------
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
 *  @version    1.1.6
 *  @author     Chris Gralike
 *  @copyright  Copyright (c) 2024 by Chris Gralike
 *  @license    GPLv3+
 *  @see        https://github.com/DonutsNL/GLPISaml/readme.md
 *  @link       https://github.com/DonutsNL/GLPISaml
 *  @since      1.0.0
 * ------------------------------------------------------------------------
 *
 * We have a GLPI state and a SAML state. This class is intended to manage
 * and validate both states and their validity at all times. It should for
 * instance allow the the plugin to invalidate a session for what ever reason
 * and force a user to login again. It also allows future SIEM integration
 * to forcefully invalidate any active sessions.
 *
 **/

namespace GlpiPlugin\Glpisaml;

use Session;
use Migration;
use Exception;
use CommonDBTM;
use DBConnection;
use GlpiPlugin\Glpisaml\Exclude;


/*
 * The goal of this object is to keep track of the login state in the database.
 * this will allow us to 'influence' the login state of a specific session if
 * we want to, for instance to forcefully log someone off or force re-authentication.
 * we can also extend this session logging for (future) SIEM purposes.
 */
class LoginState extends CommonDBTM
{
    // CLASS CONSTANTS
    public const SESSION_GLPI_NAME_ACCESSOR = 'glpiname';       // NULL -> Populated with user->name in Session::class:128 after GLPI login->init;
    public const SESSION_VALID_ID_ACCESSOR  = 'valid_id';       // NULL -> Populated with session_id() in Session::class:107 after GLPI login;
    public const STATE_ID                   = 'id';             // State identifier
    public const USER_ID                    = 'userId';         // Glpi user_id
    public const USER_NAME                  = 'userName';       // The username
    public const SESSION_ID                 = 'sessionId';      // php session_id;
    public const SESSION_NAME               = 'sessionName';    // Php session_name();
    public const GLPI_AUTHED                = 'glpiAuthed';     // Session authed by GLPI
    public const SAML_AUTHED                = 'samlAuthed';     // Session authed by SAML
    public const LOCATION                   = 'location';       // Location requested;
    public const IDP_ID                     = 'idpId';          // What IdP handled the Auth?
    public const LOGIN_DATETIME             = 'loginTime';      // When did we first see the session
    public const LAST_ACTIVITY              = 'lastClickTime';  // When did we last update the session
    public const ENFORCE_LOGOFF             = 'enforceLogoff';  // Do we want to enforce a logoff (one time)
    public const EXCLUDED_PATH              = 'excludedPath';   // If request was made using saml bypass.
    public const EXCLUDED_ACTION            = 'excludedAction'; // Action to perform on Exclude.
    public const SAML_RESPONSE              = 'serverParams';   // Stores the Saml Response
    public const SAML_REQUEST               = 'requestParams';  // Stores the SSO request
    public const PHASE                      = 'phase';          // Describes the current state GLPI, ACS, TIMEOUT, LOGGED IN, LOGGED OUT.
    public const PHASE_INITIAL              = 1;                // Initial visit
    public const PHASE_SAML_ACS             = 2;                // Performed SAML IDP call expected back at ACS
    public const PHASE_SAML_AUTH            = 3;                // Successfully performed IDP auth
    public const PHASE_GLPI_AUTH            = 4;                // Successfully performed GLPI auth
    public const PHASE_FILE_EXCL            = 5;                // Excluded file called
    public const PHASE_FORCE_LOG            = 6;                // Session forced logged off
    public const PHASE_TIMED_OUT            = 7;                // Session Timed out
    public const PHASE_LOGOFF               = 8;                // Session was logged off
    public const DATABASE                   = 'database';       // State from database?

    private $state = [];

    /**
     * Restore object if version has been cached and trigger
     * validation to make sure the session isn't hijacked
     * @since   1.0.0
     */
    public function __construct()
    {
        // Get database state (if any)
        $this->getInitialState();
    }

    /**
     * This function evaluates the state and is called after each click
     * Keeping track of the session state is important to protect GLPI
     * against all sorts of threats like SAML replays, invalid logins.
     * In the future this table might offer a basis to limit login from
     * sanctioned countries or the amount of active sessions a user is
     * allowed to have at any one time.
     *
     * The idea is NOT to implement this logic in GLPI and try to maintain
     * all possible variations, but to allow any external SIEM tool to
     * query this data using the GLPI API, do its policy logic using this data
     * and intervene (with forced logoff) if a session is found not compliant
     * with company policies.
     * @since   1.0.0
     */
    private function getInitialState(): void
    {
        // Get the globals we need
        global $DB;

        // Get 'our' decoupled sessionId
        $sessionId = $this->getSamlSessionId();

        // Figure out we are processing excluded path
        // Currently we do not reach the loginState if exclude was
        // found in the loginFlow, this is for future use.
        $this->state[LoginState::EXCLUDED_PATH] = false;
        if($this->state[LoginState::EXCLUDED_PATH] = Exclude::isExcluded()){
            $this->state[LoginState::EXCLUDED_ACTION] = Exclude::GetExcludeAction($this->state[LoginState::EXCLUDED_PATH]);
        }

        // Get the last activity
        $this->getLastActivity();

        // Get some kind of username for logging purposes.
        // Fills with remote address if no user has logged in.
        $this->setGlpiUserName();

        // See if we are a new or existing session. Use our saved
        // sessionId instead of the PHP generated ID. The PHP ID is
        // regenerated by GLPI and in some weird scenario's and does
        // not provide a stable reference for our plugin.
        // This will repopulate flags with database state which is leading.
        if(!$sessionIterator = $DB->request(['FROM' => LoginState::getTable(), 'WHERE' => [LoginState::SESSION_ID => $sessionId]])){
            throw new Exception('Could not fetch Login State from database');               //NOSONAR - We use generic Exceptions
        }

        // We should never get more then one row, if we do
        // just overwrite the values with the later entries.
        // Maybe we want to do more with this in the future
        // to prevent session hijacking scenarios.
        if($sessionIterator->numrows() > 0){
            // Populate the username field based on actual values.
            // Get all the relevant fields from the database
            foreach($sessionIterator as $sessionState)
            {
                $this->state = array_merge($this->state,[
                    LoginState::STATE_ID          => $sessionState[LoginState::STATE_ID],
                    LoginState::USER_ID           => $sessionState[LoginState::USER_ID],
                    LoginState::SESSION_ID        => $sessionState[LoginState::SESSION_ID],
                    LoginState::SESSION_NAME      => $sessionState[LoginState::SESSION_NAME],
                    LoginState::GLPI_AUTHED       => (bool) $sessionState[LoginState::GLPI_AUTHED],
                    LoginState::SAML_AUTHED       => (bool) $sessionState[LoginState::SAML_AUTHED],
                    LoginState::LOGIN_DATETIME    => $sessionState[LoginState::LOGIN_DATETIME],
                    LoginState::ENFORCE_LOGOFF    => $sessionState[LoginState::ENFORCE_LOGOFF],
                    LoginState::IDP_ID            => $sessionState[LoginState::IDP_ID],
                    LoginState::PHASE             => $sessionState[LoginState::PHASE],
                    LoginState::DATABASE          => true,
                ]);
            }
        }else{
            // Populate the GLPI state first.
            $this->getGlpiState();

            // Populate the username field
            $this->setGlpiUserName();

            // Populate session using actual
            $this->state = $this->state = array_merge($this->state,[
                LoginState::USER_ID           => 0,
                LoginState::SESSION_ID        => $sessionId,
                LoginState::SESSION_NAME      => session_name(),
                LoginState::SAML_AUTHED       => 0,
                LoginState::ENFORCE_LOGOFF    => 0,
                LoginState::EXCLUDED_PATH     => $this->state[LoginState::EXCLUDED_PATH],
                LoginState::IDP_ID            => 0,
                LoginState::DATABASE          => false,
            ]);
        }
        
        // Comment out the following if statement to make plugin log
        // all calls (including CLI) make to GLPI including all excluded ones
        if(!$this->state[LoginState::EXCLUDED_PATH]){
            // Write state to database.
            if(!$this->WriteStateToDb()){ //NOSONAR - not merging if statements by design
                throw new Exception('Could not write initial state to the state database');          //NOSONAR - We use generic Exceptions
            }
        }// Nothing.
    }

    /**
     * We need to decouple from the phpSessionId because it is being
     * manipulated by GLPI and does not offer a trustworthy point of
     * reference for our sessions. This function is designed to deal
     * with that.
     * @see     https://codeberg.org/QuinQuies/glpisaml/issues/20
     *
     * @return  string
     * @since   1.1.3
     */
    private function getSamlSessionId(): string
    {
        global $DB;
        // GLPI will reset all values except those indexes designated to be saved in src/Session.php:94
        // The way PHP generates the ID can be found here:
        // https://github.com/php/php-src/blob/d9bfe06194ae8f760cb43a3e7120d0503f327398/ext/session/session.c#L284
        // We need to use $_SESSION['glpi_plugins'][OUR_PLUGIN][OUR_KEY] in order to survive GLPI's Session::init().
        // Lets use the initial session id for now and store that safely and reuse that.
        // WARNING: This stored ID will no longer align with the php sessionId after Session::init(Auth) is invoked;
        $sessionId = session_id();
        // Set a name for our cookie.
        $cname = '__PSML';
        // If cookie was not set, set it.
        if(!isset($_COOKIE[$cname])){
            // Set our cookie with session ID.
            setcookie($cname, $sessionId, [
                'expires' => 0,
                'secure' => true,
                'httponly' => true,
                'samesite' => 'None',
            ]);
            // If the cookie array is not available
            // set it so we can reference it in the
            // next codeblocks.
            if(empty($_COOKIE[$cname])){
                $_COOKIE[$cname] = $sessionId;
            }
        }
        // Is the sessionId the same as whats stored in the Cookie?
        // The first iteration these are always the same and so the
        // database is always updated with the initial sessionId.
        // If the cookie session is different, one of two things is
        // true. Either we just performed a redirect and lost the
        // session Cookie or Session::init was called. In both cases
        // we need to update the sessionId stored in the state database.
        if($_COOKIE[$cname] != $sessionId){
            // Do not blindly trust the unencrypted cookie data
            $oldSessionId = htmlentities($_COOKIE[$cname]);
            // Update the loginstate database with the new updated sessionId
            if(!$DB->update(LoginState::getTable(), [LoginState::SESSION_ID =>  $sessionId], ['WHERE' => [LoginState::SESSION_ID => $oldSessionId]])){
                throw new Exception('Could not correctly update Login State from database');               //NOSONAR - We use generic Exceptions
            }
            // Also make sure we update the session Cookie.
            // Unset the cookie
            setcookie($cname, '', time() - 3600);
            unset($_COOKIE[$cname]);
            // Create a new cookie with the updated.
            setcookie($cname, $sessionId, [
                'expires' => 0,
                'secure' => true,
                'httponly' => true,
                'samesite' => 'None',
            ]);
        }
        // Set the SESSION['valid_id'] with current sessionId for GLPI strict

        return $sessionId;
    }

    /**
     * Write the state into the database
     * for external (SIEM) evaluation and interaction
     *
     * @return  bool
     * @since   1.0.0
     */
    private function writeStateToDb(): bool   //NOSONAR - WIP
    {
        // Register state in database;
        //if(!$this->state[LoginState::EXCLUDED_PATH]){
            if(!$this->state[LoginState::DATABASE]){
                if(!$id = $this->add($this->state)){
                    return false;
                }else{
                    // Update the state ID for future updates.
                    $this->state[LoginState::STATE_ID] = $id;
                }
            }else{
                if(!$this->update($this->state)){
                    return false;
                }
            }
        //}
        return true;
    }

    /**
     * Get and set last activity in state array
     * @since   1.0.0
     */
    private function getLastActivity(): void
    {
        // https://codeberg.org/QuinQuies/glpisaml/issues/18
        $this->state[LoginState::LOCATION] = (isset($_SERVER['REQUEST_URI'])) ? $_SERVER['REQUEST_URI'] : 'CLI';
        $this->state[LoginState::LAST_ACTIVITY] = date('Y-m-d H:i:s');
    }

    /**
     * Gets glpi state from the SESSION super global and
     * updates the state array accordingly for initial state.
     *
     * @since   1.0.0
     */
    private function getGlpiState(): void
    {
        // Verify if user is already authenticated by GLPI.
        // Name_Accessor: Populated with user->name in Session::class:128 after GLPI login->init;
        // Id_Accessor: Populated with session_id() in Session::class:107 after GLPI login;
        if (isset($_SESSION[LoginState::SESSION_GLPI_NAME_ACCESSOR]) &&
            isset($_SESSION[LoginState::SESSION_VALID_ID_ACCESSOR])  ){
            $this->state[LoginState::GLPI_AUTHED] = true;
            $this->state[LoginState::PHASE] = LoginState::PHASE_GLPI_AUTH;
        } else {
            $this->state[LoginState::GLPI_AUTHED] = false;
            $this->state[LoginState::PHASE] = LoginState::PHASE_INITIAL;
        }
    }

    /**
     * Update the loginPhase in the state database.
     * @param int   $phase ID
     * @since       1.0.0
     * @see         LoginState::PHASE_## constants for valid values
     */
    public function setPhase(int $phase): bool
    {
        // figure out if we tried to use SAML for authentication
        if($phase >= LoginState::PHASE_SAML_ACS){
            // Update the SAML_Authed flag as well
            $this->state[LoginState::SAML_AUTHED] = true;
        }
        // Process the session state
        // Consideration Is there a valid scenario where we would
        // update the session phase with a lower number than is initially present
        // degrading the session essentially?
        // would checking if the phase is always higher provide an additional layer of security?
        if($phase > 0 && $phase <= 8){
            $this->state[LoginState::PHASE] = $phase;
            return ($this->update($this->state)) ? true : false;
        }
        return false;
    }

    /**
     * Gets the current login phase
     * @return int  phase id
     * @see         LoginState::PHASE_## constants for valid values
     * @since       1.0.0
     */
    public function getPhase(): int
    {
        return (!empty($this->state[LoginState::PHASE])) ? $this->state[LoginState::PHASE] : 0;
    }

    /**
     * Sets the IdpId used in current session.
     * @param int   ConfigItem::ID pointing to IdP provider.
     * @since       1.0.0
     */
    public function setIdpId(int $idpId): bool
    {
        if($idpId > 0 && $idpId < 999){
            $this->state[LoginState::IDP_ID] = $idpId;
            return ($this->update($this->state)) ? true : false;
        }else{
            return false;
        }
    }

    /**
     * Fetches current IdpId used in current session.
     * @return int  ConfigItem::ID pointing to IdP provider.
     * @since       1.0.0
     */
    public function getIdpId(): int
    {
        return (!empty($this->state[LoginState::IDP_ID])) ? $this->state[LoginState::IDP_ID] : 0;
    }


    /**
     * Returns the EXCLUDED_PATH if set, else it returns empty.
     * @return int  ConfigItem::ID pointing to IdP provider.
     * @since       1.0.0
     */
    public function isExcluded(): string
    {
        return (!empty($this->state[LoginState::EXCLUDED_PATH])) ?  $this->state[LoginState::EXCLUDED_PATH] : '';
    }

    public function getExcludeAction(): bool
    {
        return (isset($this->state[LoginState::EXCLUDED_ACTION]) && !empty($this->state[LoginState::EXCLUDED_ACTION])) ? $this->state[LoginState::EXCLUDED_ACTION] : false;
    }

    /**
     * Adds SamlResponse to the state table
     * @param  string   json_encoded samlResponse
     * @return bool     true on success.
     * @since           1.0.0
     */
    public function setSamlResponseParams(string $samlResponse): bool
    {
        if($samlResponse > 0){
            $this->state[LoginState::SAML_RESPONSE] = $samlResponse;
            return ($this->update($this->state)) ? true : false;
        }
        return false;
    }

    /**
     * Adds SamlRequest to the state table
     * @param  string   json_encoded samlRequest
     * @return bool     true on success.
     * @since           1.0.0
     */
    public function setRequestParams(string $samlRequest): bool
    {
        if($samlRequest > 0){
            $this->state[LoginState::SAML_REQUEST] = $samlRequest;
            return ($this->update($this->state)) ? true : false;
        }
        return false;
    }

    /**
     * Get the glpi Username and set it in the state.
     * If no user was identified, use remote IP as user.
     *
     * @param   int      $idpId - identity of the IDP for which we are fetching the logging
     * @return  array    Array with logging entries (if any) else empty array;
     * @since   1.1.0
     */
    private function setGlpiUserName(): void
    {
        // Use remote ip as username if session is anonymous.
        // https://codeberg.org/QuinQuies/glpisaml/issues/18
        $altUser = (isset($_SERVER['REMOTE_ADDR'])) ? $_SERVER['REMOTE_ADDR'] : 'CLI';
        $remote = (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : $altUser;
        $this->state[LoginState::USER_NAME] = (!empty($_SESSION[LoginState::SESSION_GLPI_NAME_ACCESSOR])) ? $_SESSION[LoginState::SESSION_GLPI_NAME_ACCESSOR] : $remote;
    }

    /**
     * Gets the logging entries from the loginState database for given identity provider
     * for presentation in the logging tab.
     *
     * @param   int      $idpId - identity of the IDP for which we are fetching the logging
     * @return  array    Array with logging entries (if any) else empty array;
     * @since   1.2.0
     */
    public static function getLoggingEntries(int $idpId): array
    {
        global $DB;
        // Create an empty logging array
        $logging = [];
        // Should be a positive number.
        if(is_numeric($idpId)){
            // Fetch logging only for the given identity provider
            foreach($DB->request(['FROM' => LoginState::getTable(),
                                  'WHERE' => [LoginState::IDP_ID => $idpId],
                                  'ORDER' => [LoginState::LOGIN_DATETIME.' DESC']]) as $id => $row ){
                $logging[$id] = $row;
            }
        }
        return $logging;
    }

    /**
     * Install the LoginState DB table
     * @param   Migration $obj
     * @return  void
     * @since   1.0.0
     */
    public static function install(Migration $migration) : void
    {
        global $DB;
        $default_charset = DBConnection::getDefaultCharset();
        $default_collation = DBConnection::getDefaultCollation();
        $default_key_sign = DBConnection::getDefaultPrimaryKeySignOption();

        $table = LoginState::getTable();

        // Create the base table if it does not yet exist;
        // Do not update this table for later versions, use the migration class;
        if (!$DB->tableExists($table)) {
            // Create table
            $query = <<<SQL
            CREATE TABLE IF NOT EXISTS `$table` (
                `id`                        int {$default_key_sign} NOT NULL AUTO_INCREMENT,
                `userId`                    int {$default_key_sign} NOT NULL,
                `userName`                  varchar(255) NULL,
                `sessionId`                 varchar(255) NOT NULL,
                `sessionName`               varchar(255) NOT NULL,
                `glpiAuthed`                tinyint {$default_key_sign} NULL,
                `samlAuthed`                tinyint {$default_key_sign} NULL,
                `loginTime`                 timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
                `lastClickTime`             timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
                `location`                  text NOT NULL,
                `enforceLogoff`             tinyint {$default_key_sign} NULL,
                `excludedPath`              text NULL,
                `idpId`                     int NULL,
                `serverParams`              text NULL,
                `requestParams`             text NULL,
                `loggedOff`                 tinyint {$default_key_sign} NULL,
                `phase`                     text NULL,
                PRIMARY KEY (`id`)
            ) ENGINE=InnoDB DEFAULT CHARSET={$default_charset} COLLATE={$default_collation} ROW_FORMAT=COMPRESSED;
            SQL;
            $DB->doQuery($query) or die($DB->error());
            Session::addMessageAfterRedirect("🆗 Installed: $table.");

            // Perform optimize table
            $query = <<<SQL
            optimize table `$table`;
            SQL;
            $DB->doQuery($query) or die($DB->error());
            Session::addMessageAfterRedirect("🆗 optimized: $table.");
        }
    }

    /**
     * Uninstall the LoginState DB table
     * @param   Migration $obj
     * @return  void
     * @since   1.0.0
     */
    public static function uninstall(Migration $migration) : void
    {
        $table = LoginState::getTable();
        Session::addMessageAfterRedirect("🆗 Removed: $table.");
        $migration->dropTable($table);
    }
    
}
