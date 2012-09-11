<?php
/**
 * @category       Honeypot
 * @package        Security
 * @author         Pierre-Henry Soria <ph7software@gmail.com>
 * @copyright      (c) 2012, Pierre-Henry Soria. All Rights Reserved.
 * @license        CC-BY License - http://creativecommons.org/licenses/by/3.0/
 * @version        1.0.0
 */


/**
 * Honeypot for Joomla, one of the most used CMS in the world, most of whom know the URL location: http://your-joomla-site.com/administrator/
 */
define('IS_INDEX', 1);

require '../_config.inc.php';

session_start();

if (0 != strcmp(@$_SESSION['joomla_admin_sess'], ADMIN_COOKIE_PASS))
{
    require '_honeypot_index.inc.php'; // The fake admin interface.
}
else
{
    require '_joomla_index.inc.php'; // OK, the URL from where the person is the URL custom administration.
}

