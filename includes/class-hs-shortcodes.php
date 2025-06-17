<?php
if (!defined('ABSPATH')) { exit; }

class HS_Shortcodes {
    private $helpers, $fields;

    public function __construct($helpers, $fields) {
        $this->helpers = $helpers;
        $this->fields = $fields;
        add_action('init', [$this, 'register_shortcodes']);
    }

    public function register_shortcodes() {
        add_shortcode('hamtam_profile_form', [$this, 'render_profile_form']);
        add_shortcode('hamtam_user_listing', [$this, 'render_user_listing_page']);
        add_shortcode('hamtam_user_profile', [$this, 'render_user_profile_page']);
        add_shortcode('hamtam_requests_dashboard', [$this, 'render_requests_dashboard']);
    }

    public function render_profile_form() {
        ob_start();
        ?>
        <div id="hs-multistep-form-wrapper">
            <div id="hs-message-rejected" class="hs-message error" style="display:none;"><h4>پروفایل شما رد شده است</h4><p><strong>دلیل:</strong> <span class="rejection-reason-text"></span></p><p>لطفاً موارد ذکر شده را اصلاح کرده و مجدداً فرم را تا انتها تکمیل و ثبت نهایی کنید.</p></div>
            <div id="hs-message-approved" class="hs-message notice" style="display:none;"><p>پروفایل شما تأیید شده است. اطلاعات شما در این فرم قفل شده است.</p></div>
            <div id="hs-message-pending" class="hs-message notice" style="display:none;"><p>پروفایل شما برای بررسی ارسال شده است. تا زمان بررسی توسط مدیر، اطلاعات قفل خواهد بود.</p></div>

            <form id="hs-profile-form" method="POST" enctype="multipart/form-data" novalidate>
                <div id="hs-form-messages" class="hs-message" style="display:none;"></div>
                <?php $all_field_groups = $this->fields->get_fields(); $step_count = 1; $user_id = get_current_user_id(); foreach ($all_field_groups as $group_data): ?>
                <div class="hs-form-step" id="hs-step-<?php echo $step_count; ?>" style="<?php echo $step_count === 1 ? 'display:block;' : 'display:none;'; ?>">
                    <h3><?php echo esc_html($group_data['title']); ?></h3>
                    <?php foreach ($group_data['fields'] as $field_key => $field_attrs): $this->render_form_field($field_key, $field_attrs, $user_id); endforeach; ?>
                </div>
                <?php $step_count++; endforeach; ?>
                <div class="hs-navigation-buttons">
                    <div class="hs-loader"></div>
                    <button type="button" id="hs-prev-btn" class="hs-button secondary" style="display:none;">قبلی</button>
                    <button type="button" id="hs-next-btn" class="hs-button">بعدی</button>
                    <button type="submit" id="hs-submit-btn" class="hs-button" style="display:none;">ثبت نهایی جهت بررسی</button>
                </div>
            </form>
        </div>
        <?php
        return ob_get_clean();
    }

    private function render_form_field($key, $attrs, $user_id) {
        $meta_key = 'hs_' . $key;
        $meta_value = get_user_meta($user_id, $meta_key, true);
        $required_attr = ($attrs['required'] ?? false) ? 'required' : '';
        $pattern_attr = isset($attrs['pattern']) ? 'pattern="' . esc_attr($attrs['pattern']) . '"' : '';
        $inputmode_attr = isset($attrs['inputmode']) ? 'inputmode="' . esc_attr($attrs['inputmode']) . '"' : '';
        $validation_msg_attr = isset($attrs['validation_message']) ? 'data-validation-message="' . esc_attr($attrs['validation_message']) . '"' : '';
        
        $wrapper_attrs = '';
        if (isset($attrs['condition'])) {
            $compare_op = $attrs['condition']['compare'] ?? '==';
            $condition_value_str = is_array($attrs['condition']['value']) ? implode(',', $attrs['condition']['value']) : $attrs['condition']['value'];
            $wrapper_attrs = sprintf(
                'data-condition-field="%s" data-condition-value="%s" data-condition-compare="%s" style="display:none;"', // **FIXED**: Hide conditional fields by default
                esc_attr($attrs['condition']['field']),
                esc_attr($condition_value_str),
                esc_attr($compare_op)
            );
        }

        echo '<div class="hs-form-group" ' . $wrapper_attrs . '>';
        echo '<label for="' . esc_attr($key) . '">' . esc_html($attrs['label']) . ($required_attr ? ' <span class="required">*</span>' : '') . '</label>';
        if (!empty($attrs['description'])) { echo '<small class="hs-field-description">' . esc_html($attrs['description']) . '</small>'; }
        switch ($attrs['type']) {
            case 'text': case 'tel': case 'number':
                echo '<input type="' . esc_attr($attrs['type']) . '" id="' . esc_attr($key) . '" name="' . esc_attr($key) . '" value="' . esc_attr($meta_value) . '" ' . $required_attr . ' ' . $pattern_attr . ' ' . $inputmode_attr . ' ' . $validation_msg_attr . '><span class="hs-field-error"></span>';
                break;
            case 'textarea':
                echo '<textarea id="' . esc_attr($key) . '" name="' . esc_attr($key) . '" rows="4">' . esc_textarea($meta_value) . '</textarea><span class="hs-field-error"></span>';
                break;
            case 'select': case 'select_range':
                $options = $attrs['options'] ?? ($attrs['range'] ?? []);
                echo '<select id="' . esc_attr($key) . '" name="' . esc_attr($key) . '" ' . $required_attr . '><option value="" disabled ' . selected($meta_value, '', false) . '>انتخاب کنید</option>';
                foreach ($options as $opt_key => $opt_val) { $actual_key = ($attrs['type'] === 'select_range') ? $opt_val : $opt_key; echo '<option value="' . esc_attr($actual_key) . '" ' . selected($meta_value, $actual_key, false) . '>' . esc_html($opt_val) . '</option>'; }
                echo '</select><span class="hs-field-error"></span>';
                break;
            case 'province': case 'city':
                $is_province = ($attrs['type'] === 'province'); $target_class = $is_province ? 'hs-province-select' : 'hs-city-select'; $city_target = $is_province ? str_replace('province', 'city', $key) : '';
                echo '<select id="' . esc_attr($key) . '" name="' . esc_attr($key) . '" class="' . esc_attr($target_class) . '" data-city-target="' . esc_attr($city_target) . '" data-saved-value="' . esc_attr($meta_value) . '" ' . $required_attr . '><option value="">' . ($is_province ? 'استان را انتخاب کنید' : 'ابتدا استان را انتخاب کنید') . '</option></select><span class="hs-field-error"></span>';
                break;
            case 'date_split':
                $day = get_user_meta($user_id, $meta_key . '_day', true); $month = get_user_meta($user_id, $meta_key . '_month', true); $year = get_user_meta($user_id, $meta_key . '_year', true);
                $months = [1=>'فروردین', 2=>'اردیبهشت', 3=>'خرداد', 4=>'تیر', 5=>'مرداد', 6=>'شهریور', 7=>'مهر', 8=>'آبان', 9=>'آذر', 10=>'دی', 11=>'بهمن', 12=>'اسفند'];
                $age_range = $attrs['age_range'] ?? [18, 100]; $min_age = $age_range[0]; $max_age = $age_range[1];
                echo '<div class="hs-date-group hs-inline-fields">';
                echo '<select name="' . esc_attr($key) . '_day" ' . $required_attr . '><option value="">روز</option>'; for ($i = 1; $i <= 31; $i++) { echo '<option value="' . $i . '" ' . selected($day, $i, false) . '>' . $i . '</option>'; } echo '</select>';
                echo '<select name="' . esc_attr($key) . '_month" ' . $required_attr . '><option value="">ماه</option>'; foreach ($months as $num => $name) { echo '<option value="' . $num . '" ' . selected($month, $num, false) . '>' . $name . '</option>'; } echo '</select>';
                $current_jalali_year = (int)$this->helpers->get_current_jalali_year();
                echo '<select name="' . esc_attr($key) . '_year" ' . $required_attr . '><option value="">سال</option>'; for ($i = $current_jalali_year - $min_age; $i >= $current_jalali_year - $max_age; $i--) { echo '<option value="' . $i . '" ' . selected($year, $i, false) . '>' . $i . '</option>'; } echo '</select>';
                echo '</div><span class="hs-field-error"></span>';
                break;
            case 'range_select':
                $start_val = get_user_meta($user_id, $meta_key . '_start', true); $end_val = get_user_meta($user_id, $meta_key . '_end', true); $range = $attrs['range'] ?? [];
                echo '<div class="hs-range-group hs-inline-fields" data-range-group="' . esc_attr($key) . '">';
                echo '<select name="' . esc_attr($key) . '_start" ' . $required_attr . '><option value="">از</option>'; foreach($range as $i) { echo '<option value="' . $i . '" ' . selected($start_val, $i, false) . '>' . $i . '</option>'; } echo '</select>';
                echo '<span>تا</span>';
                echo '<select name="' . esc_attr($key) . '_end" ' . $required_attr . '><option value="">تا</option>'; foreach($range as $i) { echo '<option value="' . $i . '" ' . selected($end_val, $i, false) . '>' . $i . '</option>'; } echo '</select>';
                echo '</div><span class="hs-field-error"></span>';
                break;
            case 'file':
                echo '<input type="file" id="' . esc_attr($key) . '" name="' . esc_attr($key) . '" accept="image/jpeg,image/png" ' . $required_attr . ' data-existing-file="' . esc_attr($meta_value) . '">';
                if (!empty($meta_value)) { echo '<span class="hs-file-upload-info">فایل قبلاً آپلود شده است. برای جایگزینی، فایل جدید را انتخاب کنید.</span>'; }
                echo '<span class="hs-field-error"></span>';
                break;
        }
        echo '</div>';
    }

    public function render_user_listing_page() { ob_start(); if (!$this->helpers->check_user_access_permission()) { return ob_get_clean(); } $this->render_advanced_search_form(); $current_user_id = get_current_user_id(); $current_user_gender = get_user_meta($current_user_id, 'hs_gender', true); $target_gender = ($current_user_gender == 'male') ? 'female' : 'male'; $args = ['role' => 'hs_approved', 'exclude' => [$current_user_id], 'meta_query' => ['relation' => 'AND', ['key' => 'hs_gender', 'value' => $target_gender]]]; if (!empty($_GET['hs_search'])) { $meta_query = $args['meta_query']; if (!empty($_GET['residence_city'])) { $meta_query[] = ['key' => 'hs_residence_city', 'value' => sanitize_text_field($_GET['residence_city']), 'compare' => 'LIKE']; } if (!empty($_GET['min_age']) && is_numeric($_GET['min_age'])) { $max_birth_year = (int)$this->helpers->get_current_jalali_year() - (int)$_GET['min_age']; $meta_query[] = ['key' => 'hs_birth_date', 'value' => $max_birth_year . '/12/30', 'compare' => '<=', 'type' => 'CHAR']; } if (!empty($_GET['max_age']) && is_numeric($_GET['max_age'])) { $min_birth_year = (int)$this->helpers->get_current_jalali_year() - (int)$_GET['max_age']; $meta_query[] = ['key' => 'hs_birth_date', 'value' => $min_birth_year . '/01/01', 'compare' => '>=', 'type' => 'CHAR']; } $args['meta_query'] = $meta_query; } $user_query = new WP_User_Query($args); if (!empty($user_query->get_results())) { echo '<div class="hs-user-grid">'; foreach ($user_query->get_results() as $user) { $this->render_user_card($user); } echo '</div>'; } else { echo '<p class="hs-message">کاربری با مشخصات مورد نظر شما یافت نشد.</p>'; } return ob_get_clean(); }
    
    private function render_advanced_search_form() { ?> <div class="hs-advanced-search"> <button id="hs-toggle-search" class="hs-button">جستجوی پیشرفته</button> <form id="hs-search-form" method="get" action="" style="display:none;"> <input type="hidden" name="hs_search" value="1"> <div class="hs-form-row"> <div class="hs-form-group"><label for="min_age">حداقل سن:</label><input type="number" name="min_age" value="<?php echo isset($_GET['min_age']) ? esc_attr($_GET['min_age']) : ''; ?>"></div> <div class="hs-form-group"><label for="max_age">حداکثر سن:</label><input type="number" name="max_age" value="<?php echo isset($_GET['max_age']) ? esc_attr($_GET['max_age']) : ''; ?>"></div> </div> <div class="hs-form-row"> <div class="hs-form-group"><label for="residence_city">شهر محل زندگی:</label><input type="text" name="residence_city" value="<?php echo isset($_GET['residence_city']) ? esc_attr($_GET['residence_city']) : ''; ?>"></div> </div> <button type="submit" class="hs-button">جستجو</button> </form> </div> <?php }
    
    public function render_user_card($user) { $user_id = $user->ID; $first_name = get_user_meta($user_id, 'hs_first_name', true) ?: $user->first_name; $city = get_user_meta($user_id, 'hs_residence_city', true); $age = $this->helpers->calculate_age(get_user_meta($user_id, 'hs_birth_date', true)); $profile_uuid = get_user_meta($user_id, 'hs_profile_uuid', true) ?: $this->helpers->generate_profile_uuid_on_register($user_id); $profile_url = $this->helpers->get_profile_page_url($profile_uuid); echo '<div class="hs-user-card">'; echo '<h3>' . esc_html($first_name) . '</h3>'; echo '<p>سن: ' . esc_html($age) . ' سال</p>'; echo '<p>شهر: ' . esc_html($city) . '</p>'; echo '<a href="' . esc_url($profile_url) . '" class="hs-button">مشاهده پروفایل</a>'; echo '</div>'; }

    public function render_user_profile_page() { ob_start(); if (!is_user_logged_in()) { echo '<p class="hs-message error">برای مشاهده این صفحه، ابتدا وارد شوید.</p>'; return ob_get_clean(); } if (!isset($_GET['uuid'])) { echo '<p class="hs-message error">شناسه کاربر نامعتبر است.</p>'; return ob_get_clean(); } $uuid = sanitize_text_field($_GET['uuid']); $users = get_users(['meta_key' => 'hs_profile_uuid', 'meta_value' => $uuid, 'number' => 1, 'fields' => 'all']); if (empty($users)) { echo '<p class="hs-message error">کاربر مورد نظر یافت نشد.</p>'; return ob_get_clean(); } $user = $users[0]; $target_user_id = $user->ID; $current_user_id = get_current_user_id(); $active_request = $this->helpers->get_user_active_sent_request($current_user_id); if ($active_request && $active_request->receiver_id != $target_user_id) { echo '<p class="hs-message error">شما یک درخواست فعال با کاربر دیگری دارید و نمی‌توانید این پروفایل را مشاهده کنید.</p>'; return ob_get_clean(); } echo '<div class="hs-profile-container">'; $last_seen = get_user_meta($target_user_id, 'hs_last_seen', true); if ($last_seen) echo '<p class="hs-last-seen">آخرین بازدید: ' . esc_html($this->helpers->format_last_seen($last_seen)) . '</p>'; $first_name = get_user_meta($target_user_id, 'hs_first_name', true); $last_name = get_user_meta($target_user_id, 'hs_last_name', true); echo '<h1>پروفایل ' . esc_html($first_name . ' ' . $last_name) . '</h1>'; $this->render_profile_action_buttons($current_user_id, $target_user_id); echo '<div class="hs-profile-details">'; $all_field_groups = $this->fields->get_fields(); foreach ($all_field_groups as $group) { foreach ($group['fields'] as $key => $attrs) { if (empty($attrs['public'])) continue; $meta_value = get_user_meta($target_user_id, 'hs_' . $key, true); if (empty($meta_value)) continue; echo '<div class="hs-profile-field"><strong>' . esc_html($attrs['label']) . ':</strong> <span>'; if(isset($attrs['is_age'])) { echo esc_html($this->helpers->calculate_age($meta_value)) . ' سال'; } elseif (isset($attrs['options'])) { echo esc_html($attrs['options'][$meta_value] ?? $meta_value); } else { echo nl2br(esc_html($meta_value)); } echo '</span></div>'; } } echo '</div></div>'; return ob_get_clean(); }
    
    private function render_profile_action_buttons($current_user_id, $target_user_id) { $interaction = $this->helpers->get_interaction_between_users($current_user_id, $target_user_id); echo '<div class="hs-profile-actions">'; if ($interaction) { if ($interaction->status === 'pending' && $interaction->receiver_id == $current_user_id) { echo '<button class="hs-button" data-action="accept" data-request-id="' . $interaction->id . '">تایید درخواست</button>'; echo '<button class="hs-button danger" data-action="reject" data-request-id="' . $interaction->id . '">رد درخواست</button>'; } elseif ($interaction->status === 'pending' && $interaction->sender_id == $current_user_id) { echo '<p class="hs-message notice">شما برای این کاربر درخواست ارسال کرده‌اید و منتظر پاسخ هستید.</p>'; echo '<button class="hs-button warning" id="hs-cancel-request-btn" data-request-id="' . $interaction->id . '" data-is-male="' . (get_user_meta($current_user_id, 'hs_gender', true) === 'male' ? 'true' : 'false') . '">لغو درخواست</button>'; } elseif ($interaction->status === 'accepted') { echo '<p class="hs-message notice">درخواست شما تایید شده و منتظر بررسی نهایی توسط مدیر است.</p>'; echo '<button class="hs-button warning" id="hs-cancel-request-btn" data-request-id="' . $interaction->id . '" data-is-male="' . (get_user_meta($current_user_id, 'hs_gender', true) === 'male' ? 'true' : 'false') . '">لغو آشنایی</button>'; } else { echo '<p class="hs-message notice">وضعیت فعلی شما با این کاربر: ' . esc_html($this->helpers->get_status_label($interaction->status)) . '</p>'; } } elseif (!$this->helpers->get_user_active_sent_request($current_user_id)) { echo '<button id="hs-send-request-btn" class="hs-button" data-receiver-id="' . $target_user_id . '">درخواست آشنایی</button>'; } else { echo '<p class="hs-message notice">شما یک درخواست فعال با کاربر دیگری دارید و نمی‌توانید درخواست جدیدی ارسال کنید.</p>'; } echo '</div>'; }
    
    public function render_requests_dashboard() { ob_start(); if (!$this->helpers->check_user_access_permission(false)) { return ob_get_clean(); } $user_id = get_current_user_id(); $active_request = $this->helpers->get_user_active_sent_request($user_id); if ($active_request) { echo '<div class="hs-message notice hs-active-request-box">'; echo '<h4>شما یک درخواست آشنایی فعال دارید</h4>'; echo '<p>تا زمان مشخص شدن وضعیت این درخواست، امکان مشاهده سایر کاربران را ندارید.</p>'; $receiver = get_userdata($active_request->receiver_id); if ($receiver) { $this->render_user_card($receiver); } echo '</div>'; } global $wpdb; $table_name = $wpdb->prefix . 'hs_requests'; echo '<h2>درخواست‌های من</h2>'; $incoming_requests = $wpdb->get_results($wpdb->prepare("SELECT * FROM {$table_name} WHERE receiver_id = %d AND status = 'pending' ORDER BY request_date DESC", $user_id)); echo '<h3>درخواست‌های دریافتی</h3>'; if ($incoming_requests) { echo '<ul class="hs-requests-list">'; foreach ($incoming_requests as $request) { $sender = get_userdata($request->sender_id); if (!$sender) continue; $profile_uuid = get_user_meta($sender->ID, 'hs_profile_uuid', true); $profile_url = $this->helpers->get_profile_page_url($profile_uuid); echo '<li>درخواست از طرف <a href="'.esc_url($profile_url).'">'.esc_html($sender->display_name).'</a> <span class="hs-request-actions"><button class="hs-button" data-action="accept" data-request-id="'.$request->id.'">تایید</button> <button class="hs-button danger" data-action="reject" data-request-id="'.$request->id.'">رد</button></span></li>'; } echo '</ul>'; } else { echo '<p>شما درخواست دریافتی جدیدی ندارید.</p>'; } $outgoing_requests = $wpdb->get_results($wpdb->prepare("SELECT * FROM {$table_name} WHERE sender_id = %d ORDER BY request_date DESC", $user_id)); echo '<h3>تاریخچه درخواست‌های ارسالی</h3>'; if ($outgoing_requests) { echo '<ul class="hs-requests-list">'; foreach ($outgoing_requests as $request) { $receiver = get_userdata($request->receiver_id); if (!$receiver) continue; $profile_uuid = get_user_meta($receiver->ID, 'hs_profile_uuid', true); $profile_url = $this->helpers->get_profile_page_url($profile_uuid); echo '<li>درخواست برای <a href="'.esc_url($profile_url).'">'.esc_html($receiver->display_name).'</a> - وضعیت: '.esc_html($this->helpers->get_status_label($request->status)).'</li>'; } echo '</ul>'; } else { echo '<p>شما تاکنون درخواستی ارسال نکرده‌اید.</p>'; } return ob_get_clean(); }
}
