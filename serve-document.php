<?php
/**
 * Hamtam Secure File Server - v2
 *
 * This version explicitly sets the HTTP status header to 200 OK after security checks
 * to prevent the WordPress theme's 404 template from hijacking the request.
 */

// We don't use SHORTINIT to ensure all necessary functions are available.
// We will manually control the execution flow and exit properly.
require_once(dirname(__FILE__) . '/../../../wp-load.php');

// Security Check 1: Verify Nonce
if (!isset($_GET['_wpnonce']) || !wp_verify_nonce(sanitize_key($_GET['_wpnonce']), 'hs_serve_secure_file_nonce_action')) {
    wp_die('لینک شما منقضی شده یا نامعتبر است.', 'خطای امنیتی', ['response' => 403]);
}

// Security Check 2: Check User Authentication and Capabilities
if (!is_user_logged_in() || !current_user_can('manage_options')) {
    wp_die('شما دسترسی لازم برای مشاهده این فایل را ندارید.', 'عدم دسترسی', ['response' => 403]);
}

// **CRITICAL FIX**: Send a 200 OK header immediately after security checks.
// This tells WordPress that this is a valid page and prevents it from loading the 404 template.
status_header(200);

// Get parameters from the URL
$user_id = isset($_GET['user_id']) ? intval($_GET['user_id']) : 0;
$doc_key = isset($_GET['doc_key']) ? sanitize_text_field($_GET['doc_key']) : '';

if (!$user_id || !$doc_key) {
    wp_die('اطلاعات درخواست نامعتبر است. پارامترهای لازم ارسال نشده‌اند.');
}

// Get file information from user meta
$file_info = get_user_meta($user_id, $doc_key, true);
if (empty($file_info) || !is_array($file_info) || empty($file_info['file_name'])) {
    wp_die('اطلاعات فایل برای این کاربر در دیتابیس یافت نشد.');
}

// Construct the absolute path to the file
$private_dir_name = defined('HS_PRIVATE_DOCS_DIR_NAME') ? HS_PRIVATE_DOCS_DIR_NAME : 'hamtam_private_documents';
$wp_upload_dir = wp_get_upload_dir();
$private_dir_path = trailingslashit($wp_upload_dir['basedir']) . $private_dir_name;
$absolute_path = trailingslashit($private_dir_path) . $file_info['file_name'];

if (file_exists($absolute_path)) {
    // Set appropriate headers for the browser to display the file
    header('Content-Type: ' . esc_attr($file_info['mime_type']));
    header('Content-Disposition: inline; filename="' . esc_attr($file_info['original_name']) . '"');
    header('Content-Length: ' . filesize($absolute_path));
    header('Cache-Control: no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    
    // Clean any possible output buffering before sending the file
    if (ob_get_level()) {
        ob_end_clean();
    }
    
    // Output the file and immediately stop all further script execution
    readfile($absolute_path);
    die();
    
} else {
    // If the file does not exist on the server, send a clear 404 error
    status_header(404);
    wp_die('فایل در سرور یافت نشد. این مشکل می‌تواند به دلیل پاک شدن فایل یا مشکلات سطح دسترسی پوشه‌ها باشد.');
}
