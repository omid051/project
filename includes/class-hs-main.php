<?php
if (!defined('ABSPATH')) { exit; }

final class HS_Main {
    private static $instance = null;
    public $setup, $ajax, $shortcodes, $admin, $helpers, $fields;

    public static function get_instance() {
        if (null === self::$instance) { self::$instance = new self(); }
        return self::$instance;
    }

    private function __construct() {
        $this->load_dependencies();
        $this->fields = new HS_Fields();
        $this->helpers = new HS_Helpers();
        $this->setup = new HS_Setup();
        $this->ajax = new HS_Ajax($this->helpers, $this->fields);
        $this->shortcodes = new HS_Shortcodes($this->helpers, $this->fields);
        $this->admin = new HS_Admin($this->helpers, $this->fields);
        $this->add_actions_and_filters();
    }

    private function load_dependencies() {
        $files = ['data/iran-cities.php', 'class-hs-setup.php', 'class-hs-fields.php', 'class-hs-helpers.php', 'class-hs-shortcodes.php', 'class-hs-ajax.php', 'class-hs-admin.php'];
        foreach ($files as $file) { require_once HS_PLUGIN_PATH . 'includes/' . $file; }
    }

    private function add_actions_and_filters() {
        add_action('wp_enqueue_scripts', [$this, 'enqueue_scripts']);
        add_action('init', [$this->helpers, 'update_last_seen']);
        add_action('user_register', [$this->helpers, 'generate_profile_uuid_on_register']);
        add_action('template_redirect', [$this, 'handle_redirects']);
        add_action('hs_auto_cancel_old_requests_hook', [$this, 'auto_cancel_old_requests']);
        
        // **NEW**: Hook to check ban status on every page load
        add_action('init', [$this, 'check_user_ban_status'], 1);
    }

    // **NEW**: Function to check if the current user is banned
    public function check_user_ban_status() {
        if (is_user_logged_in() && !current_user_can('manage_options') && !wp_doing_ajax()) {
            $user_id = get_current_user_id();
            $banned_until = get_user_meta($user_id, '_hs_banned_until', true);

            if (!empty($banned_until) && time() < $banned_until) {
                $remaining_time = human_time_diff(time(), $banned_until);
                
                // Load the banned user template and stop further execution
                include_once HS_PLUGIN_PATH . 'templates/banned-user-page.php';
                exit();
            }
        }
    }

    public function enqueue_scripts() {
        wp_enqueue_style('hs-styles', HS_PLUGIN_URL . 'assets/css/main.css', [], '5.0.0');
        wp_enqueue_script('hs-scripts', HS_PLUGIN_URL . 'assets/js/main.js', ['jquery'], '5.0.0', true);
        wp_localize_script('hs-scripts', 'hs_ajax_data', [
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce'    => wp_create_nonce('hs_ajax_nonce'),
            'messages' => [
                'field_required' => 'این فیلد الزامی است.',
                'final_submission_error'   => 'لطفاً خطاهای مشخص شده در فرم را برطرف کنید.',
                'final_submission_success' => 'اطلاعات شما با موفقیت ثبت شد و برای بررسی ارسال گردید.',
                'error_saving' => 'خطایی در ذخیره‌سازی اطلاعات رخ داد.',
            ],
            'provinces_cities' => hs_get_iran_provinces_cities(),
        ]);
    }

    public function handle_redirects() {
        if (is_admin() || !is_user_logged_in()) return;
        $user_id = get_current_user_id();
        global $post;
        if (!is_a($post, 'WP_Post')) return;
        $is_listing_page = has_shortcode($post->post_content, 'hamtam_user_listing');
        $active_sent_request = $this->helpers->get_user_active_sent_request($user_id);
        if ($active_sent_request && $is_listing_page) {
            $dashboard_url = $this->helpers->get_dashboard_page_url();
            if ($dashboard_url && !is_page(basename($dashboard_url))) {
                wp_redirect($dashboard_url);
                exit;
            }
        }
    }

    public function auto_cancel_old_requests() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'hs_requests';
        $time_limit = current_time('mysql', 1);
        $twenty_four_hours_ago = date('Y-m-d H:i:s', strtotime('-24 hours', strtotime($time_limit)));
        $wpdb->query($wpdb->prepare("UPDATE {$table_name} SET status = 'auto_cancelled' WHERE status = 'pending' AND request_date < %s", $twenty_four_hours_ago));
    }
}
