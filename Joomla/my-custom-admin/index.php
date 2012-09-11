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
 * You need to move this administration folder with a name difficult to find (example: http://your-joomla-site.com/my-repertoire-very-difficult-to-find-93393994/).
 */
define('IS_INDEX', 1);

require '../_config.inc.php';

session_start();

$_SESSION['joomla_admin_sess'] = ADMIN_COOKIE_PASS; // Joomla Login is OK
header('Location: ../administrator/');
