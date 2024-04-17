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
 *  @version    1.1.0
 *  @author     Chris Gralike
 *  @copyright  Copyright (c) 2024 by Chris Gralike
 *  @license    GPLv3+
 *  @see        https://github.com/DonutsNL/GLPISaml/readme.md
 *  @link       https://github.com/DonutsNL/GLPISaml
 *  @since      1.0.0
 * ------------------------------------------------------------------------
 **/

 /**
 * Be carefull with PSR4 Namespaces when extending common GLPI objects.
 * Only Characters are allowed in namespaces extending glpi Objects.
 * @see https://github.com/pluginsGLPI/example/issues/51
 * @see https://github.com/DonutsNL/phpsaml2/issues/6
 */
namespace GlpiPlugin\Glpisaml;

use Session;
use Migration;
use CommonDBTM;
use DBConnection;
use GlpiPlugin\Glpisaml\Config\ConfigItem;
use GlpiPlugin\Glpisaml\Config\ConfigEntity;

/**
 * Class Handles the installation and listing of configuration front/config.php
 * is is also the baseclass that extends the CommonDBTM GLPI object. All other
 * glpisaml config classes reference this class for CRUD operations on the config
 * database.
 */
class Config extends CommonDBTM
{
    /**
     * Tell DBTM to keep history
     * @var    bool     - $dohistory
     */
    public $dohistory = true;

    /**
     * Tell CommonGLPI to use config (Setup->Setup in UI) rights.
     * @var    string   - $rightname
     */
    public static $rightname = 'config';

    /**
     * Overloads missing canCreate Setup right and returns canUpdate instead
     *
     * @return bool     - Returns true if profile assgined Setup->Setup->Update right
     * @see             - https://github.com/pluginsGLPI/example/issues/50
     */
    public static function canCreate(): bool
    {
        return static::canUpdate();
    }

    /**
     * Overloads missing canDelete Setup right and returns canUpdate instead
     *
     * @return bool     - Returns true if profile assgined Setup->Setup->Update right
     * @see             - https://github.com/pluginsGLPI/example/issues/50
     */
    public static function canDelete(): bool
    {
        return static::canUpdate();
    }

    /**
     * Overloads missing canPurge Setup right and returns canUpdate instead
     *
     * @return bool     - Returns true if profile assgined Setup->Setup->Update right
     * @see             - https://github.com/pluginsGLPI/example/issues/50
     */
    public static function canPurge(): bool
    {
        return static::canUpdate();
    }

    /**
     * returns class friendly TypeName
     * @param  int      - $nb return plural or singular friendly name.
     * @return string   - returns translated friendly name.
     */
    public static function getTypeName($nb = 0): string
    {
        return __('SAML Providers', PLUGIN_NAME);
    }

    /**
     * Returns class icon to use in menus and tabs
     *
     * @return string   - returns Font Awesom icon classname.
     * @see             - https://fontawesome.com/search
     */
    public static function getIcon(): string
    {
        return 'fa-regular fa-address-card';
    }

    /**
     * Added links for user convenience
     * @see CommonGLPI::getAdditionalMenuLinks()
     * @see https://codeberg.org/QuinQuies/glpisaml/issues/8
     **/
    public static function getAdditionalMenuLinks() {
        $links[__('Excluded paths', PLUGIN_NAME)] = PLUGIN_GLPISAML_WEBDIR.'/front/exclude.php';
        $links[__('JIT rules', PLUGIN_NAME)] = PLUGIN_GLPISAML_WEBDIR.'/front/rulesaml.php';
        return $links;
    }

    /**
     * Provides search options for DBTM.
     * Do not rely on this, @see CommonDBTM::searchOptions instead.
     *
     * @return array  $tab  - returns searchOptions
     * @see                 - https://glpi-developer-documentation.readthedocs.io/en/master/devapi/search.html
     * @see                 - https://codeberg.org/QuinQuies/glpisaml/issues/9
     */
    function rawSearchOptions(): array                          //NOSONAR - phpcs:ignore PSR1.Function.CamelCapsMethodName
    {
        $tab = parent::rawSearchOptions();
        $tab[] = [
            'id'                 => '1',
            'table'              => $this->getTable(),
            'field'              => ConfigEntity::ID,
            'name'               => __('ID'),
            'massiveaction'      => false, // implicit field is id
            'datatype'           => 'itemlink'
        ];
        $tab[] = [
            'id'                 => '2',
            'table'              => $this->getTable(),
            'field'              => ConfigEntity::NAME,
            'name'               => __('Name'),
            'massiveaction'      => false,
            'datatype'           => 'itemlink'
        ];
        $tab[] = [
            'id'                 => '3',
            'table'              => $this->getTable(),
            'field'              => ConfigEntity::IDP_ENTITY_ID,
            'name'               => __('Idp entity ID'),
            'massiveaction'      => false,
            'datatype'           => 'text'
        ];
        $tab[] = [
            'id'                 => '4',
            'table'              => $this->getTable(),
            'field'              => ConfigEntity::IS_ACTIVE,
            'name'               => __('Is active'),
            'massiveaction'      => false,
            'datatype'           => 'bool'
        ];

        // Lets not be as verbose as default GLPI objects when we dont need to.
        // continue tabId index where we left off.
        $index = 5;
        foreach((new ConfigEntity())->getFields() as $field)
        {
            $field['list'] = false;
           // skip the following fields
            if($field[ConfigItem::FIELD] != ConfigEntity::ID            &&
               $field[ConfigItem::FIELD] != ConfigEntity::NAME          &&
               $field[ConfigItem::FIELD] != ConfigEntity::IDP_ENTITY_ID &&
               $field[ConfigItem::FIELD] != ConfigEntity::IS_ACTIVE     &&
               $field[ConfigItem::FIELD] != ConfigEntity::IS_DELETED    ){
                // Remap DB fields to Search datatypes
                if(strstr($field[ConfigItem::TYPE], 'varchar') ){
                    $field[ConfigItem::TYPE] = 'string';
                }elseif($field[ConfigItem::TYPE] == 'tinyint' ){
                    $field[ConfigItem::TYPE] = 'bool';
                }elseif($field[ConfigItem::TYPE] == 'text' ){
                    $field[ConfigItem::TYPE] = 'text';
                }elseif($field[ConfigItem::TYPE] == 'timestamp' ){
                    $field[ConfigItem::TYPE] = 'date';
                }elseif(strstr($field[ConfigItem::TYPE], 'int') ){
                    $field[ConfigItem::TYPE] = 'number';
                }
                // Build tab array
                $tab[] = [
                    'id'                 => $index,
                    'table'              => self::getTable(),
                    'field'              => $field[ConfigItem::FIELD],
                    'name'               => __(str_replace('_', ' ', ucfirst($field[ConfigItem::FIELD]))),
                    'datatype'           => $field[ConfigItem::TYPE],
                    'list'               => $field['list'],
                ];
                // Only increase index if we processed an item.
                $index++;
            }
        }
        return $tab;
    }


    /**
     * Get all valid configurations and return config buttons only if config is valid
     * and active.
     * @return  array
     * @see                             - src/Loginflow/showLoginScreen()
     */
    public static function getLoginButtons(int $length): array
    {
        // Get global DB object to query the configTable.
        global $DB;
        // Define the array used to store the buttons (if any)
        $tplvars = [];
        // $length is used to strip the length of the button name to fit the button.
        $length = (is_numeric($length)) ? $length : 255;
        // Iterate throught the IDP config rows and generate the buttons for twig template.
        foreach( $DB->request(['FROM' => self::getTable()]) as $value)
        {
            // Only populate buttons that are considered valid by ConfigEntity;
            $configEntity = new ConfigEntity($value[ConfigEntity::ID]);
            if($configEntity->isValid() && $configEntity->isActive()){
                $tplvars['buttons'][] = ['id'      => $value[ConfigEntity::ID],
                                        'icon'    => $value[ConfigEntity::CONF_ICON],
                                        'name'    => sprintf("%.".$length."s", $value[ConfigEntity::NAME]) ];
            }
        }
        // Return the buttons (if any) else empty array.
        return $tplvars;
    }


    /**
     * Install table needed for Ticket Filter configuration dropdowns
     * @param   Migration $migration    - Plugin migration information;
     * @return  void
     * @see                             - GLPISaml/hook.php
     */
    public static function install(Migration $migration): void
    {
        global $DB;
        $default_charset    = DBConnection::getDefaultCharset();
        $default_collation  = DBConnection::getDefaultCollation();
        $default_key_sign   = DBConnection::getDefaultPrimaryKeySignOption();
        $table              = self::getTable();

        // Create the base table if it does not yet exist;
        // Dont update this table for later versions, use the migration class;
        if (!$DB->tableExists($table)) {
            $migration->displayMessage("Installing $table");
            $query = <<<SQL
            CREATE TABLE `$table` (
            `id`                            INT {$default_key_sign} NOT NULL auto_increment,
            `name`                          VARCHAR(255) NOT NULL,
            `conf_domain`                   VARCHAR(50) NOT NULL,
            `conf_icon`                     VARCHAR(50) NOT NULL,
            `enforce_sso`                   tinyint NOT NULL DEFAULT '0',
            `proxied`                       tinyint NOT NULL DEFAULT '0',
            `strict`                        tinyint NOT NULL DEFAULT '0',
            `debug`                         tinyint NOT NULL DEFAULT '0',
            `user_jit`                      tinyint NOT NULL DEFAULT '0',
            `sp_certificate`                TEXT NOT NULL,
            `sp_private_key`                TEXT NOT NULL,
            `sp_nameid_format`              VARCHAR(128) NOT NULL,
            `idp_entity_id`                 VARCHAR(128) NOT NULL,
            `idp_single_sign_on_service`    VARCHAR(128) NOT NULL,
            `idp_single_logout_service`     VARCHAR(128) NOT NULL,
            `idp_certificate`               TEXT NOT NULL,
            `requested_authn_context`       TEXT NOT NULL,
            `requested_authn_context_comparison` VARCHAR(25) NOT NULL,
            `security_nameidencrypted`      tinyint NOT NULL DEFAULT '0',
            `security_authnrequestssigned`  tinyint NOT NULL DEFAULT '0',
            `security_logoutrequestsigned`  tinyint NOT NULL DEFAULT '0',
            `security_logoutresponsesigned` tinyint NOT NULL DEFAULT '0',
            `compress_requests`             tinyint NOT NULL DEFAULT '0',
            `compress_responses`            tinyint NOT NULL DEFAULT '0',
            `validate_xml`                  tinyint NOT NULL DEFAULT '0',
            `validate_destination`          tinyint NOT NULL DEFAULT '0',
            `lowercase_url_encoding`        tinyint NOT NULL DEFAULT '0',
            `comment`                       text NULL,
            `is_active`                     tinyint NOT NULL DEFAULT '0',
            `is_deleted`                    tinyint NOT NULL default '0',
            `date_creation`                 timestamp NULL DEFAULT CURRENT_TIMESTAMP,
            `date_mod`                      timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (`id`)
            ) ENGINE=InnoDB DEFAULT CHARSET={$default_charset} COLLATE={$default_collation} ROW_FORMAT=COMPRESSED;
            SQL;
            $DB->doQuery($query) or die($DB->error());
            Session::addMessageAfterRedirect("🆗 Installed: $table.");
        }
    }

    /**
     * Uninstall table needed for Ticket Filter configuration dropdowns
     * @param   Migration $migration    - Plugin migration information;
     * @return  void
     * @see                             - GLPISaml/hook.php
     */
    public static function uninstall(Migration $migration): void
    {
        $table = self::getTable();
        // Make this smarter in the future. Never create a backup
        // when the source table is empty and an existing table is
        // populated! Allow user to restore from backup table. Current
        // implementation will 'overwrite' the backup with an empty
        // table if uninstall->reinstall->uninstall is performed.
        $migration->backupTables([$table]);
        Session::addMessageAfterRedirect("🆗 backup: $table.");
        $migration->dropTable($table);
        Session::addMessageAfterRedirect("🆗 Removed: $table.");
    }
}
