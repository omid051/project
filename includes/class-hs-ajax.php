<?php
if (!defined('ABSPATH')) { exit; }

class HS_Ajax {
    private $helpers, $fields;
    private $current_user_id_for_upload = 0; // Property to hold user ID during upload

    public function __construct($helpers, $fields) {
        $this->helpers = $helpers;
        $this->fields = $fields;
        $this->add_ajax_events();
    }

    private function add_ajax_events() {
        $actions = ['get_user_status', 'save_profile_form', 'approve_user', 'reject_user', 'send_request', 'handle_request_action', 'cancel_request', 'serve_secure_file'];
        foreach ($actions as $action) {
            add_action('wp_ajax_hs_' . $action, [$this, $action]);
        }
        
        // Hook to hide private attachments from the media library
        add_filter('ajax_query_attachments_args', [$this, 'hide_private_attachments_from_media_library']);
    }

    public function get_user_status() {
        check_ajax_referer('hs_ajax_nonce', 'nonce');
        $user_id = get_current_user_id();
        if (!$user_id) {
            wp_send_json_error();
            return;
        }
        
        $user = get_userdata($user_id);
        $user_roles = (array) $user->roles;

        $is_editable = in_array('subscriber', $user_roles) || in_array('hs_rejected', $user_roles);
        $rejection_reason_raw = get_user_meta($user_id, 'hs_rejection_reason', true);
        $rejection_reason_html = !empty($rejection_reason_raw) ? nl2br(esc_html($rejection_reason_raw)) : '';

        wp_send_json_success([
            'is_editable' => $is_editable,
            'roles' => $user_roles,
            'rejection_reason_html' => $rejection_reason_html
        ]);
    }

    public function save_profile_form() {
        check_ajax_referer('hs_ajax_nonce', 'nonce');
        $this->current_user_id_for_upload = get_current_user_id();
        $form_data = [];
        if(isset($_POST['form_data'])) {
            parse_str($_POST['form_data'], $form_data);
        }

        if (!empty($form_data['national_code'])) {
            $national_code = sanitize_text_field($form_data['national_code']);
            $existing_users = get_users(['meta_key' => 'hs_national_code', 'meta_value' => $national_code, 'exclude' => [$this->current_user_id_for_upload], 'fields' => 'ID']);
            if (!empty($existing_users)) {
                wp_send_json_error(['message' => 'این کد ملی قبلاً در سیستم ثبت شده است.']);
                return;
            }
        }

        $all_field_groups = $this->fields->get_fields();
        foreach ($all_field_groups as $group) {
            foreach ($group['fields'] as $field_key => $attrs) {
                if (in_array($attrs['type'], ['range_select'])) {
                    $start_key = $field_key . '_start'; $end_key = $field_key . '_end';
                    if (isset($form_data[$start_key])) { update_user_meta($this->current_user_id_for_upload, 'hs_' . $start_key, sanitize_text_field($form_data[$start_key])); }
                    if (isset($form_data[$end_key])) { update_user_meta($this->current_user_id_for_upload, 'hs_' . $end_key, sanitize_text_field($form_data[$end_key])); }
                } elseif ($attrs['type'] === 'date_split') {
                    $day_key = $field_key . '_day'; $month_key = $field_key . '_month'; $year_key = $field_key . '_year';
                    if (isset($form_data[$day_key]) && isset($form_data[$month_key]) && isset($form_data[$year_key])) {
                        $day = sanitize_text_field($form_data[$day_key]);
                        $month = sanitize_text_field($form_data[$month_key]);
                        $year = sanitize_text_field($form_data[$year_key]);
                        if ($year && $month && $day) {
                            $formatted_month = str_pad($month, 2, '0', STR_PAD_LEFT);
                            $formatted_day = str_pad($day, 2, '0', STR_PAD_LEFT);
                            update_user_meta($this->current_user_id_for_upload, 'hs_' . $field_key, "{$year}/{$formatted_month}/{$formatted_day}");
                            update_user_meta($this->current_user_id_for_upload, 'hs_' . $day_key, $day); 
                            update_user_meta($this->current_user_id_for_upload, 'hs_' . $month_key, $month); 
                            update_user_meta($this->current_user_id_for_upload, 'hs_' . $year_key, $year);
                        }
                    }
                } elseif (isset($form_data[$field_key])) {
                    $value = stripslashes_deep($form_data[$field_key]);
                    $sanitized_value = is_array($value) ? array_map('sanitize_text_field', $value) : sanitize_textarea_field($value);
                    update_user_meta($this->current_user_id_for_upload, 'hs_' . $field_key, $sanitized_value);
                }
            }
        }

        // **NEW & FIXED**: Complete file handling rewrite
        if (!empty($_FILES)) {
            require_once(ABSPATH . 'wp-admin/includes/file.php');
            require_once(ABSPATH . 'wp-admin/includes/image.php');
            require_once(ABSPATH . 'wp-admin/includes/media.php');
            
            // Add the filter to rename files just before the loop
            add_filter('wp_handle_upload_prefilter', [$this, 'rename_secure_file'], 10, 1);

            foreach ($_FILES as $file_key => $file) {
                if (isset($file['name']) && $file['size'] > 0) {
                    $upload_overrides = ['test_form' => false];
                    $upload = wp_handle_upload($file, $upload_overrides);

                    if ($upload && !isset($upload['error'])) {
                        // Move the file to our secure directory
                        $this->move_to_secure_directory($upload);
                        
                        // Create attachment
                        $attachment = [
                            'guid'           => $upload['url'],
                            'post_mime_type' => $upload['type'],
                            'post_title'     => preg_replace( '/\.[^.]+$/', '', basename( $upload['file'] ) ),
                            'post_content'   => '',
                            'post_status'    => 'inherit'
                        ];
                        
                        $attach_id = wp_insert_attachment($attachment, $upload['file']);
                        if (!is_wp_error($attach_id)) {
                            // Mark as private
                            update_post_meta($attach_id, '_hs_private_attachment', true);
                            
                            $attach_data = wp_generate_attachment_metadata($attach_id, $upload['file']);
                            wp_update_attachment_metadata($attach_id, $attach_data);
                            update_user_meta($this->current_user_id_for_upload, 'hs_' . $file_key, $attach_id);
                        }
                    } else {
                        wp_send_json_error(['message' => $upload['error']]);
                        return;
                    }
                }
            }
            // Remove the filter after the loop
            remove_filter('wp_handle_upload_prefilter', [$this, 'rename_secure_file'], 10);
        }
    
        if (isset($_POST['final_submission']) && $_POST['final_submission'] === 'true') {
            update_user_meta($this->current_user_id_for_upload, 'hs_submission_status', 'finalized');
            $user = new WP_User($this->current_user_id_for_upload);
            $user->set_role('hs_pending');
            delete_user_meta($this->current_user_id_for_upload, 'hs_rejection_reason');
            clean_user_cache($this->current_user_id_for_upload);
        }
        wp_send_json_success(['message' => 'اطلاعات با موفقیت ذخیره شد.']);
    }
    
    // **NEW**: Renames file to {national_code}-{index}.ext
    public function rename_secure_file($file) {
        $user_id = $this->current_user_id_for_upload;
        if (!$user_id) return $file;

        $form_data = [];
        if(isset($_POST['form_data'])) {
            parse_str($_POST['form_data'], $form_data);
        }
        $national_code = !empty($form_data['national_code']) ? sanitize_text_field($form_data['national_code']) : 'user_' . $user_id;

        $file_index_key = 'hs_uploaded_file_index';
        $current_index = (int)get_user_meta($user_id, $file_index_key, true);
        $new_index = $current_index + 1;
        update_user_meta($user_id, $file_index_key, $new_index);
        
        $path_parts = pathinfo($file['name']);
        $extension = isset($path_parts['extension']) ? strtolower($path_parts['extension']) : '';
        $new_filename = $national_code . '-' . $new_index . '.' . $extension;
        
        $file['name'] = $new_filename;
        return $file;
    }

    // **NEW**: Moves the uploaded file to the final secure directory
    private function move_to_secure_directory(&$upload) {
        $upload_dir = wp_upload_dir();
        $secure_dir_path = trailingslashit($upload_dir['basedir']) . HS_SECURE_UPLOADS_DIR_NAME;
        
        // Ensure the secure directory exists
        if (!is_dir($secure_dir_path)) {
            wp_mkdir_p($secure_dir_path);
            // Also create .htaccess to deny access
            $htaccess_path = trailingslashit($secure_dir_path) . '.htaccess';
            if (!file_exists($htaccess_path)) {
                @file_put_contents($htaccess_path, 'Deny from all');
            }
        }
        
        $new_file = trailingslashit($secure_dir_path) . basename($upload['file']);
        
        if (rename($upload['file'], $new_file)) {
            $upload['file'] = $new_file;
            // The URL is not publicly accessible, so we clear it.
            $upload['url'] = '';
        }
    }
    
    // **NEW**: Hides private attachments from the main media library grid
    public function hide_private_attachments_from_media_library($query) {
        if (!current_user_can('manage_options')) {
            return $query;
        }
        $query['meta_query'][] = [
            'key'     => '_hs_private_attachment',
            'compare' => 'NOT EXISTS',
        ];
        return $query;
    }

    public function serve_secure_file() {
        check_ajax_referer('hs_serve_secure_file_nonce_action');
        if (!current_user_can('manage_options')) { wp_die('Access Denied'); }
        
        $file_id = isset($_GET['file_id']) ? intval($_GET['file_id']) : 0;
        if(!$file_id) { wp_die('Invalid file ID.'); }

        $file_path = get_attached_file($file_id, true);

        if ($file_path && file_exists($file_path)) {
            header('Content-Type: ' . get_post_mime_type($file_id));
            header('Content-Disposition: inline; filename="' . basename($file_path) . '"');
            header('Content-Length: ' . filesize($file_path));
            header("Cache-Control: no-cache, must-revalidate");
            header("Expires: 0");
            @readfile($file_path);
            exit;
        } else {
            status_header(404);
            wp_die('فایل یافت نشد یا دسترسی به آن امکان‌پذیر نیست.');
        }
    }

    // --- Other methods remain unchanged ---
    public function approve_user() { check_ajax_referer('hs_admin_nonce', 'nonce'); if (!current_user_can('manage_options')) { wp_send_json_error(['message' => 'شما دسترسی لازم برای این کار را ندارید.']); } $user_id = isset($_POST['user_id']) ? intval($_POST['user_id']) : 0; if (!$user_id) { wp_send_json_error(['message' => 'شناسه کاربر نامعتبر است.']); } update_user_meta($user_id, 'hs_submission_status', 'approved'); delete_user_meta($user_id, 'hs_rejection_reason'); $user = new WP_User($user_id); $user->set_role('hs_approved'); clean_user_cache($user_id); wp_send_json_success(['message' => 'کاربر با موفقیت تأیید شد.', 'new_role_name' => 'تأیید شده']); }
    public function reject_user() { check_ajax_referer('hs_admin_nonce', 'nonce'); if (!current_user_can('manage_options')) { wp_send_json_error(['message' => 'شما دسترسی لازم برای این کار را ندارید.']); } $user_id = isset($_POST['user_id']) ? intval($_POST['user_id']) : 0; $reason = isset($_POST['reason']) ? sanitize_textarea_field($_POST['reason']) : ''; if (!$user_id || empty($reason)) { wp_send_json_error(['message' => 'شناسه کاربر یا دلیل رد نامعتبر است.']); } update_user_meta($user_id, 'hs_submission_status', 'rejected'); update_user_meta($user_id, 'hs_rejection_reason', $reason); $user = new WP_User($user_id); $user->set_role('hs_rejected'); clean_user_cache($user_id); wp_send_json_success(['message' => 'کاربر رد شد و پیام برای او ارسال گردید.', 'new_role_name' => 'رد شده']); }
    public function send_request() { check_ajax_referer('hs_ajax_nonce', 'nonce'); $sender_id = get_current_user_id(); $receiver_id = isset($_POST['receiver_id']) ? intval($_POST['receiver_id']) : 0; if (!$receiver_id || $sender_id == $receiver_id) { wp_send_json_error(['message' => 'اطلاعات نامعتبر است.']); } if (!$this->helpers->check_user_access_permission(true)) { wp_send_json_error(['message' => 'شما اجازه ارسال درخواست را ندارید.']); } if ($this->helpers->get_interaction_between_users($sender_id, $receiver_id)) { wp_send_json_error(['message' => 'شما قبلاً برای این کاربر درخواست ارسال کرده‌اید.']); } global $wpdb; $result = $wpdb->insert($wpdb->prefix . 'hs_requests', ['sender_id' => $sender_id, 'receiver_id' => $receiver_id, 'status' => 'pending', 'request_date' => current_time('mysql')], ['%d', '%d', '%s', '%s']); if ($result) { wp_send_json_success(['message' => 'درخواست شما با موفقیت ارسال شد.']); } else { wp_send_json_error(['message' => 'خطایی در ارسال درخواست رخ داد.']); } }
    public function handle_request_action() { check_ajax_referer('hs_ajax_nonce', 'nonce'); $user_id = get_current_user_id(); $request_id = isset($_POST['request_id']) ? intval($_POST['request_id']) : 0; $action = isset($_POST['request_action']) ? sanitize_text_field($_POST['request_action']) : ''; if (!$request_id || !in_array($action, ['accept', 'reject'])) { wp_send_json_error(['message' => 'اطلاعات نامعتبر است.']); } global $wpdb; $table_name = $wpdb->prefix . 'hs_requests'; $request = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$table_name} WHERE id = %d", $request_id)); if (!$request || $request->receiver_id != $user_id || $request->status !== 'pending') { wp_send_json_error(['message' => 'شما اجازه انجام این کار را ندارید.']); } $new_status = ($action === 'accept') ? 'accepted' : 'rejected'; $result = $wpdb->update($table_name, ['status' => $new_status, 'response_date' => current_time('mysql')], ['id' => $request_id]); if ($result) { wp_send_json_success(['message' => 'پاسخ شما با موفقیت ثبت شد.', 'action' => $action]); } else { wp_send_json_error(['message' => 'خطایی در ثبت پاسخ رخ داد.']); } }
    public function cancel_request() { check_ajax_referer('hs_ajax_nonce', 'nonce'); $user_id = get_current_user_id(); $request_id = isset($_POST['request_id']) ? intval($_POST['request_id']) : 0; $reason = isset($_POST['reason']) ? sanitize_textarea_field($_POST['reason']) : ''; if (!$request_id || empty($reason)) { wp_send_json_error(['message' => 'دلیل لغو اجباری است.']); } global $wpdb; $table_name = $wpdb->prefix . 'hs_requests'; $request = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$table_name} WHERE id = %d", $request_id)); if (!$request || ($request->sender_id != $user_id && $request->receiver_id != $user_id)) { wp_send_json_error(['message' => 'این درخواست متعلق به شما نیست.']); } $result = $wpdb->update($table_name, ['status' => 'cancelled', 'cancellation_reason' => $reason, 'cancelled_by' => $user_id, 'response_date' => current_time('mysql')], ['id' => $request_id]); if ($result) { if (get_user_meta($user_id, 'hs_gender', true) === 'male') { update_user_meta($user_id, '_hs_cancellation_lock_until', time() + DAY_IN_SECONDS); wp_send_json_success(['message' => 'درخواست شما لغو شد. حساب شما به مدت ۲۴ ساعت قفل خواهد بود.']); } else { wp_send_json_success(['message' => 'درخواست شما با موفقیت لغو شد.']); } } else { wp_send_json_error(['message' => 'خطایی در لغو درخواست رخ داد.']); } }
}
