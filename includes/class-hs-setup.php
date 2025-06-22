<?php
if (!defined('ABSPATH')) { exit; }

class HS_Setup {
    public function __construct() {
         add_action('init', [$this, 'check_and_create_dependencies']);
    }

    public static function activate() {
        self::create_roles();
        self::create_requests_table();
        // The secure uploads dir is now created on-demand by the AJAX class.
        if (!wp_next_scheduled('hs_auto_cancel_old_requests_hook')) {
            wp_schedule_event(time(), 'hourly', 'hs_auto_cancel_old_requests_hook');
        }
        update_option('hs_db_version', '1.0');
    }

    public static function deactivate() {
        self::remove_roles();
        wp_clear_scheduled_hook('hs_auto_cancel_old_requests_hook');
    }

    public function check_and_create_dependencies() {
        self::create_roles(); // Ensures roles exist on every load
        if (get_option('hs_db_version') !== '1.0') {
            self::create_requests_table();
            update_option('hs_db_version', '1.0');
        }
        // The secure uploads dir is now created on-demand, so no check is needed here.
    }

    private static function create_roles() {
        if (get_role('hs_approved')) {
            return; // Roles already exist
        }
        $subscriber_caps = get_role('subscriber')->capabilities;
        $roles = ['hs_pending' => 'در انتظار بررسی', 'hs_approved' => 'تأیید شده', 'hs_rejected' => 'رد شده', 'hs_blocked' => 'مسدود شده', 'hs_inactive' => 'غیرفعال'];
        foreach ($roles as $slug => $name) { add_role($slug, $name, $subscriber_caps); }
    }

    private static function remove_roles() {
        $roles = ['hs_pending', 'hs_approved', 'hs_rejected', 'hs_blocked', 'hs_inactive'];
        foreach ($roles as $role) { remove_role($role); }
    }
    
    private static function create_requests_table() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'hs_requests';
        $charset_collate = $wpdb->get_charset_collate();
        $sql = "CREATE TABLE $table_name (
            id mediumint(9) NOT NULL AUTO_INCREMENT, sender_id bigint(20) UNSIGNED NOT NULL, receiver_id bigint(20) UNSIGNED NOT NULL, status varchar(50) DEFAULT 'pending' NOT NULL,
            request_date datetime DEFAULT '0000-00-00 00:00:00' NOT NULL, response_date datetime, cancellation_reason text, cancelled_by bigint(20) UNSIGNED,
            admin_decision varchar(50) DEFAULT 'new' NOT NULL, admin_id bigint(20) UNSIGNED, admin_decision_date datetime,
            PRIMARY KEY (id), KEY sender_id (sender_id), KEY receiver_id (receiver_id)
        ) $charset_collate;";
        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
    }
    
    // **REMOVED**: The create_secure_uploads_dir function is now obsolete.
}
