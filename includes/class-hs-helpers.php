<?php
if (!defined('ABSPATH')) { exit; }

class HS_Helpers {

    public function update_last_seen() {
        if (is_user_logged_in()) {
            update_user_meta(get_current_user_id(), 'hs_last_seen', time());
        }
    }

    public function format_last_seen($timestamp) {
        if (empty($timestamp) || !is_numeric($timestamp)) { return 'نامشخص'; }
        $now = current_time('timestamp');
        $diff = $now - $timestamp;
        if ($diff < HOUR_IN_SECONDS) return 'لحظاتی پیش';
        if ($diff < DAY_IN_SECONDS) return 'امروز';
        if ($diff < 2 * DAY_IN_SECONDS) return 'دیروز';
        return 'مدتی پیش';
    }
    
    public function check_user_access_permission($check_lock = true) {
        if (!is_user_logged_in()) {
            echo '<p class="hs-message error">برای دسترسی به این بخش، ابتدا باید وارد شوید.</p>';
            return false;
        }
        $user_id = get_current_user_id();
        $user = get_userdata($user_id);
        if (!in_array('hs_approved', (array)$user->roles)) {
            echo '<p class="hs-message error">برای دسترسی به این بخش، پروفایل شما باید ابتدا توسط مدیر تایید شود.</p>';
            return false;
        }
        if ($check_lock) {
            $active_request = $this->get_user_active_sent_request($user_id);
            if ($active_request) {
                echo '<div class="hs-message notice"><h4>شما یک درخواست آشنایی فعال دارید</h4><p>تا زمان مشخص شدن وضعیت این درخواست، امکان مشاهده سایر کاربران را ندارید.</p></div>';
                $receiver = get_userdata($active_request->receiver_id);
                if ($receiver) {
                    $shortcode_class = new HS_Shortcodes($this, new HS_Fields());
                    $shortcode_class->render_user_card($receiver);
                }
                return false;
            }
            $lock_until = get_user_meta($user_id, '_hs_cancellation_lock_until', true);
            if ($lock_until && time() < $lock_until) {
                echo '<p class="hs-message error">حساب شما به دلیل لغو درخواست قفل شده است. زمان باقی‌مانده تا آزادسازی: ' . human_time_diff(time(), $lock_until) . '</p>';
                return false;
            }
        }
        return true;
    }

    public function calculate_age($birth_date_str) {
        if (empty($birth_date_str) || !preg_match('/^(\d{4})[\/\-](\d{1,2})[\/\-](\d{1,2})$/', $birth_date_str, $matches)) return 'نامشخص';
        list($jy, $jm, $jd) = array_slice($matches, 1);
        list($gy, $gm, $gd) = $this->jalali_to_gregorian((int)$jy, (int)$jm, (int)$jd);
        try {
            $birth_date = new DateTime("$gy-$gm-$gd");
            $today = new DateTime('today');
            return $birth_date->diff($today)->y;
        } catch (Exception $e) { return 'نامشخص'; }
    }
    
    public function jalali_to_gregorian($jy, $jm, $jd) {
        $g_d_m = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
        $jy += 1595; $days = -355668 + (365 * $jy) + (((int)($jy / 33)) * 8) + ((int)((($jy % 33) + 3) / 4)) + $jd + (($jm < 7) ? ($jm - 1) * 31 : (($jm - 7) * 30) + 186);
        $gy = 400 * ((int)($days / 146097)); $days %= 146097;
        if ($days > 36524) { $gy += 100 * ((int)(--$days / 36524)); $days %= 36524; if ($days >= 365) $days++; }
        $gy += 4 * ((int)($days / 1461)); $days %= 1461;
        if ($days > 365) { $gy += (int)(--$days / 365); $days %= 365; }
        $gd = $days + 1;
        foreach ($g_d_m as $gm_key => $v) { if ($gd <= $v) { $gm = $gm_key; break; } }
        $gd -= $g_d_m[--$gm];
        return [$gy, $gm, $gd];
    }
    
    public function get_current_jalali_year() { return date_i18n('Y'); }

    public function get_user_active_sent_request($user_id) {
        global $wpdb;
        return $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}hs_requests WHERE sender_id = %d AND status IN ('pending', 'accepted')", $user_id));
    }

    public function get_interaction_between_users($user1_id, $user2_id) {
        global $wpdb;
        return $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}hs_requests WHERE (sender_id = %d AND receiver_id = %d) OR (sender_id = %d AND receiver_id = %d) ORDER BY request_date DESC LIMIT 1", $user1_id, $user2_id, $user2_id, $user1_id));
    }

    public function lift_cancellation_lock($user_id) { delete_user_meta($user_id, '_hs_cancellation_lock_until'); }

    public function generate_profile_uuid_on_register($user_id) { if (!get_user_meta($user_id, 'hs_profile_uuid', true)) { update_user_meta($user_id, 'hs_profile_uuid', wp_generate_uuid4()); } }
    
    public function get_profile_page_url($uuid) { $page = get_page_by_path('user-profile', OBJECT, 'page'); return $page ? add_query_arg('uuid', $uuid, get_permalink($page->ID)) : home_url('/'); }
    
    public function get_dashboard_page_url() { $page = get_page_by_path('requests-dashboard', OBJECT, 'page'); return $page ? get_permalink($page->ID) : home_url('/'); }

    public function get_status_label($status) {
        $labels = ['pending' => 'در انتظار پاسخ', 'accepted' => 'تایید شده توسط کاربر', 'rejected' => 'رد شده', 'cancelled' => 'لغو شده توسط کاربر', 'auto_cancelled' => 'لغو خودکار', 'cancelled_by_admin' => 'لغو توسط مدیر', 'admin_confirm' => 'تایید نهایی', 'admin_reject' => 'رد نهایی'];
        return $labels[$status] ?? $status;
    }

    public function get_admin_decision_label($decision) {
        $labels = ['new' => 'جدید', 'admin_confirm' => 'تایید شده', 'admin_reject' => 'رد شده', 'cancelled_by_admin' => 'لغو شده'];
        return $labels[$decision] ?? $decision;
    }
}