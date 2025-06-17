<?php
if (!defined('ABSPATH')) { exit; }

class HS_Admin {
    private $helpers, $fields;

    public function __construct($helpers, $fields) {
        $this->helpers = $helpers;
        $this->fields = $fields;
        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_scripts']);
        add_action('show_user_profile', [$this, 'add_profile_actions_box']);
        add_action('edit_user_profile', [$this, 'add_profile_actions_box']);
    }

    public function enqueue_scripts($hook) {
        if (strpos($hook, 'hamtam-') === false && $hook !== 'user-edit.php' && $hook !== 'profile.php') { return; }
        
        wp_enqueue_style('hs-admin-styles', HS_PLUGIN_URL . 'assets/css/admin.css', [], '7.0.0');
        wp_enqueue_script('hs-admin-js', HS_PLUGIN_URL . 'assets/js/admin.js', ['jquery'], '7.0.0', true);
        wp_localize_script('hs-admin-js', 'hs_admin_data', ['nonce' => wp_create_nonce('hs_admin_nonce')]);
    }

    public function add_admin_menu() {
        $pending_count = count(get_users(['role' => 'hs_pending']));
        $bubble = $pending_count > 0 ? ' <span class="awaiting-mod">' . $pending_count . '</span>' : '';
        
        add_menu_page('همتام', 'همتام', 'manage_options', 'hamtam-requests', [$this, 'render_requests_page'], 'dashicons-groups', 25);
        add_submenu_page('hamtam-requests', 'مدیریت درخواست‌ها', 'مدیریت درخواست‌ها', 'manage_options', 'hamtam-requests', [$this, 'render_requests_page']);
        add_submenu_page('hamtam-requests', 'بررسی پروفایل‌ها', 'بررسی پروفایل‌ها' . $bubble, 'manage_options', 'hamtam-profiles', [$this, 'render_profiles_page']);
    }

    public function render_requests_page() {
        global $wpdb; $table_name = $wpdb->prefix . 'hs_requests';
        if (isset($_GET['action'], $_GET['_wpnonce']) && wp_verify_nonce(sanitize_text_field($_GET['_wpnonce']), 'hs_admin_action')) {
            $request_id = isset($_GET['request_id']) ? intval($_GET['request_id']) : 0;
            $user_id = isset($_GET['user_id']) ? intval($_GET['user_id']) : 0;
            $action = sanitize_text_field($_GET['action']);
            if ($request_id) {
                if ($action === 'admin_confirm' || $action === 'admin_reject') { $wpdb->update($table_name, ['admin_decision' => $action], ['id' => $request_id]); echo '<div class="notice notice-success is-dismissible"><p>تصمیم شما با موفقیت ثبت شد.</p></div>';
                } elseif ($action === 'admin_cancel') { $wpdb->update($table_name, ['status' => 'cancelled_by_admin', 'admin_decision' => 'cancelled_by_admin'], ['id' => $request_id]); echo '<div class="notice notice-success is-dismissible"><p>درخواست با موفقیت توسط شما لغو شد.</p></div>'; }
            }
            if ($user_id && $action === 'lift_lock') { $this->helpers->lift_cancellation_lock($user_id); echo '<div class="notice notice-success is-dismissible"><p>محدودیت ۲۴ ساعته کاربر با موفقیت لغو شد.</p></div>'; }
        }
        $active_tab = isset($_GET['tab']) ? sanitize_text_field($_GET['tab']) : 'mutual';
        ?>
        <div class="wrap hs-admin-wrap">
            <h1>مدیریت درخواست‌های آشنایی</h1>
            <h2 class="nav-tab-wrapper">
                <a href="?page=hamtam-requests&tab=mutual" class="nav-tab <?php echo $active_tab == 'mutual' ? 'nav-tab-active' : ''; ?>">دوطرفه (منتظر تایید)</a>
                <a href="?page=hamtam-requests&tab=all" class="nav-tab <?php echo $active_tab == 'all' ? 'nav-tab-active' : ''; ?>">همه درخواست‌ها</a>
            </h2>
            <?php $this->render_requests_table($active_tab); ?>
        </div>
        <?php
    }

    private function render_requests_table($tab) {
        global $wpdb; $table_name = $wpdb->prefix . 'hs_requests';
        $query = "SELECT r.*, sender.display_name as sender_name, receiver.display_name as receiver_name FROM {$table_name} r JOIN {$wpdb->users} sender ON r.sender_id = sender.ID JOIN {$wpdb->users} receiver ON r.receiver_id = receiver.ID";
        if ($tab === 'mutual') { $query .= " WHERE r.status = 'accepted'"; }
        $requests = $wpdb->get_results($query . " ORDER BY r.request_date DESC"); ?>
        <table class="wp-list-table widefat fixed striped">
            <thead><tr><th>ارسال کننده</th><th>دریافت کننده</th><th>تاریخ درخواست</th><th>وضعیت کاربر</th><th>تصمیم ادمین</th><th>عملیات</th></tr></thead>
            <tbody>
            <?php if ($requests): foreach ($requests as $request): $sender_lock = get_user_meta($request->sender_id, '_hs_cancellation_lock_until', true); ?>
                <tr>
                    <td><?php echo esc_html($request->sender_name); ?> (<a href="<?php echo get_edit_user_link($request->sender_id); ?>" target="_blank">ویرایش</a>)
                        <?php if ($sender_lock && time() < $sender_lock): $lift_lock_url = wp_nonce_url(admin_url('admin.php?page=hamtam-requests&action=lift_lock&user_id=' . $request->sender_id), 'hs_admin_action'); ?>
                            <br><a href="<?php echo esc_url($lift_lock_url); ?>" style="color:red;" title="این کاربر محدود شده است.">(لغو محدودیت)</a>
                        <?php endif; ?>
                    </td>
                    <td><?php echo esc_html($request->receiver_name); ?> (<a href="<?php echo get_edit_user_link($request->receiver_id); ?>" target="_blank">ویرایش</a>)</td>
                    <td><?php echo esc_html(wp_date('Y/m/d H:i', strtotime($request->request_date))); ?></td>
                    <td><span class="hs-status-badge status-<?php echo esc_attr($request->status); ?>"><?php echo esc_html($this->helpers->get_status_label($request->status)); ?></span></td>
                    <td><span class="hs-status-badge status-<?php echo esc_attr($request->admin_decision); ?>"><?php echo esc_html($this->helpers->get_admin_decision_label($request->admin_decision)); ?></span></td>
                    <td>
                        <div class="hs-admin-actions">
                        <?php if ($request->admin_decision === 'new'): ?>
                            <?php if ($request->status === 'accepted'): 
                                $confirm_url = wp_nonce_url(admin_url('admin.php?page=hamtam-requests&action=admin_confirm&request_id=' . $request->id), 'hs_admin_action');
                                $reject_url = wp_nonce_url(admin_url('admin.php?page=hamtam-requests&action=admin_reject&request_id=' . $request->id), 'hs_admin_action');
                            ?>
                            <a href="<?php echo esc_url($confirm_url); ?>" class="button button-primary">تایید نهایی</a>
                            <a href="<?php echo esc_url($reject_url); ?>" class="button button-secondary">رد نهایی</a>
                            <?php endif; ?>
                            <?php if (in_array($request->status, ['pending', 'accepted'])): 
                                $cancel_url = wp_nonce_url(admin_url('admin.php?page=hamtam-requests&action=admin_cancel&request_id=' . $request->id), 'hs_admin_action');
                            ?>
                                <a href="<?php echo esc_url($cancel_url); ?>" class="button">لغو درخواست</a>
                            <?php endif; ?>
                        <?php else: echo '---'; endif; ?>
                        </div>
                    </td>
                </tr>
                 <?php if (!empty($request->cancellation_reason)): ?>
                <tr class="cancellation-reason-row"><td colspan="6"><strong>دلیل لغو:</strong> <?php echo esc_html($request->cancellation_reason); ?> (توسط: <?php echo esc_html(get_userdata($request->cancelled_by)->display_name); ?>)</td></tr>
                <?php endif; ?>
            <?php endforeach; else: ?>
                <tr><td colspan="6">هیچ درخواستی در این بخش یافت نشد.</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
        <?php
    }

    public function render_profiles_page() { ?>
        <div class="wrap hs-admin-wrap">
            <h1>کاربران در انتظار بررسی</h1>
            <p>در این صفحه، لیست کاربرانی که فرم ثبت‌نام را تکمیل کرده و منتظر تأیید شما هستند، نمایش داده می‌شود.</p>
            <table class="wp-list-table widefat fixed striped">
                <thead><tr><th>نام کاربری</th><th>نام و نام خانوادگی</th><th>ایمیل</th><th>تاریخ ثبت‌نام</th><th>عملیات</th></tr></thead>
                <tbody>
                <?php
                $pending_users = get_users(['role__in' => ['hs_pending', 'hs_rejected']]);
                if (!empty($pending_users)) {
                    foreach ($pending_users as $user) {
                        $edit_link = get_edit_user_link($user->ID);
                        $full_name = get_user_meta($user->ID, 'hs_first_name', true) . ' ' . get_user_meta($user->ID, 'hs_last_name', true);
                        $status = in_array('hs_rejected', (array)$user->roles) ? ' <span style="color:red;">(رد شده)</span>' : '';
                        ?>
                        <tr>
                            <td><strong><a href="<?php echo esc_url($edit_link); ?>"><?php echo esc_html($user->user_login); ?></a><?php echo $status; ?></strong></td>
                            <td><?php echo esc_html($full_name); ?></td>
                            <td><?php echo esc_html($user->user_email); ?></td>
                            <td><?php echo date_i18n('Y/m/d', strtotime($user->user_registered)); ?></td>
                            <td><a href="<?php echo esc_url($edit_link); ?>" class="button">مشاهده و بررسی پروفایل</a></td>
                        </tr>
                        <?php
                    }
                } else { echo '<tr><td colspan="5">هیچ کاربر جدیدی در انتظار بررسی نیست.</td></tr>'; }
                ?>
                </tbody>
            </table>
        </div>
        <?php
    }

    public function add_profile_actions_box($user) {
        if (!current_user_can('manage_options')) return;
        $user_roles = (array) $user->roles;
        $relevant_roles = ['hs_pending', 'hs_approved', 'hs_rejected', 'hs_blocked', 'hs_inactive'];
        if (empty(array_intersect($relevant_roles, $user_roles))) { return; }
        ?>
        <div id="hs-admin-review-box" class="postbox">
            <h2 class="hndle"><span>عملیات پروفایل همتام</span></h2>
            <div class="inside">
                 <div id="hs-profile-docs">
                    <h3>مدارک بارگذاری شده</h3>
                    <?php 
                    $doc_fields = array_filter($this->fields->get_fields()['documents']['fields'], fn($a) => $a['type'] === 'file');
                    $has_docs = false;
                    foreach ($doc_fields as $key => $attrs) {
                        // **FIXED**: Link generation now points to the new handler with user_id and doc_key
                        $file_data = get_user_meta($user->ID, 'hs_' . $key, true);
                        if(!empty($file_data) && is_array($file_data)) {
                            $has_docs = true;
                            $nonce = wp_create_nonce('hs_serve_secure_file_nonce_action');
                            $file_url = admin_url('admin-ajax.php?action=hs_serve_secure_file&user_id=' . $user->ID . '&doc_key=hs_' . $key . '&_wpnonce=' . $nonce);
                            echo '<p><strong>' . esc_html($attrs['label']) . ':</strong> <a href="' . esc_url($file_url) . '" target="_blank">مشاهده فایل (' . esc_html($file_data['original_name']) . ')</a></p>';
                        }
                    }
                    if(!$has_docs) echo '<p>هیچ مدرکی توسط این کاربر بارگذاری نشده است.</p>';
                    ?>
                </div>
                <hr>
                <div class="hs-admin-actions">
                    <div id="hs-action-message" style="display:none;" class="notice"></div>
                    <button type="button" class="button button-primary" id="hs-approve-btn" data-user-id="<?php echo $user->ID; ?>">تأیید پروفایل</button>
                    <button type="button" class="button button-secondary" id="hs-reject-btn-prompt">رد پروفایل</button>
                    <span class="spinner" style="float: none; vertical-align: middle;"></span>
                    <div id="rejection-reason-wrapper" style="display:none; margin-top:15px;">
                        <p><label for="rejection_reason"><strong>دلیل رد پروفایل (این پیام به کاربر نمایش داده می‌شود):</strong></label></p>
                        <textarea id="rejection_reason" rows="3" style="width: 100%;"></textarea>
                        <button type="button" class="button button-danger" id="hs-reject-btn-confirm" data-user-id="<?php echo $user->ID; ?>" style="margin-top: 10px;">ثبت دلیل و رد کردن نهایی</button>
                        <button type="button" class="button button-secondary" id="hs-reject-cancel-btn" style="margin-top: 10px;">انصراف</button>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }
}
