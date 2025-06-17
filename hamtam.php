<?php
/**
 * Plugin Name: Hamtam
 * Description: A comprehensive system for user profiles and matchmaking.
 * Version: 5.0.0
 * Author: Hamtam
 * Text Domain: hamtam
 * Domain Path: /languages
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!defined('HS_PLUGIN_FILE')) {
    define('HS_PLUGIN_FILE', __FILE__);
}
if (!defined('HS_PLUGIN_PATH')) {
    define('HS_PLUGIN_PATH', plugin_dir_path(HS_PLUGIN_FILE));
}
if (!defined('HS_PLUGIN_URL')) {
    define('HS_PLUGIN_URL', plugin_dir_url(HS_PLUGIN_FILE));
}

// **FIXED**: Using a new, more descriptive constant for the private directory.
if (!defined('HS_PRIVATE_DOCS_DIR_NAME')) {
    define('HS_PRIVATE_DOCS_DIR_NAME', 'hamtam_private_documents');
}

require_once HS_PLUGIN_PATH . 'includes/class-hs-main.php';

add_action('plugins_loaded', ['HS_Main', 'get_instance']);

register_activation_hook(HS_PLUGIN_FILE, ['HS_Setup', 'activate']);
register_deactivation_hook(HS_PLUGIN_FILE, ['HS_Setup', 'deactivate']);
