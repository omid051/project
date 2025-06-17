<?php
if (!defined('ABSPATH')) { exit; }

class HS_Fields {
    public static function get_fields() {
        return [
            'personal' => [ 'title' => '۱. اطلاعات شخصی', 'fields' => [
                'first_name' => ['label' => 'نام', 'type' => 'text', 'required' => true, 'public' => true, 'pattern' => '^[\u0600-\u06FF\s]+$', 'validation_message' => 'لطفاً فقط از حروف فارسی استفاده کنید.'],
                'last_name' => ['label' => 'نام خانوادگی', 'type' => 'text', 'required' => true, 'public' => false, 'pattern' => '^[\u0600-\u06FF\s]+$', 'validation_message' => 'لطفاً فقط از حروف فارسی استفاده کنید.', 'description' => 'به کاربران دیگر نمایش داده نمی‌شود.'],
                'mobile_phone' => ['label' => 'تلفن همراه', 'type' => 'tel', 'required' => true, 'public' => false, 'pattern' => '^09[0-9]{9}$', 'inputmode' => 'numeric', 'validation_message' => 'فرمت شماره موبایل صحیح نیست (مثال: 09123456789).'],
                'national_code' => ['label' => 'کد ملی', 'type' => 'tel', 'required' => true, 'public' => false, 'pattern' => '^[0-9]{10}$', 'inputmode' => 'numeric', 'validation_message' => 'کد ملی باید ۱۰ رقم و فقط عدد باشد.'],
                'birth_date' => ['label' => 'تاریخ تولد', 'type' => 'date_split', 'required' => true, 'public' => true, 'is_age' => true, 'age_range' => [18, 100]],
                'gender' => ['label' => 'جنسیت', 'type' => 'select', 'required' => true, 'public' => true, 'options' => ['male' => 'آقا', 'female' => 'خانم']],
                'birth_province' => ['label' => 'استان محل تولد', 'type' => 'province', 'required' => true, 'public' => true],
                'birth_city' => ['label' => 'شهر محل تولد', 'type' => 'city', 'required' => true, 'public' => true],
                'religion' => ['label' => 'دین', 'type' => 'select', 'required' => true, 'public' => true, 'options' => ['muslim_shia' => 'مسلمان (شیعه)', 'muslim_sunni' => 'مسلمان (سنی)', 'muslim_other' => 'مسلمان (سایر)', 'christian' => 'مسیحی', 'jewish' => 'کلیمی', 'zoroastrian' => 'زرتشتی', 'other' => 'سایر']],
                'about_me' => ['label' => 'درباره من', 'type' => 'textarea', 'required' => false, 'public' => true],
            ]],
            'family' => [ 'title' => '۲. خانواده', 'fields' => [
                 'father_birth_date' => ['label' => 'تاریخ تولد پدر', 'type' => 'date_split', 'required' => true, 'public' => false, 'age_range' => [20, 120]],
                 'father_is_alive' => ['label' => 'پدر در قید حیات', 'type' => 'select', 'required' => true, 'public' => false, 'options' => ['yes' => 'بله', 'no' => 'خیر']],
                 'mother_birth_date' => ['label' => 'تاریخ تولد مادر', 'type' => 'date_split', 'required' => true, 'public' => false, 'age_range' => [20, 120]],
                 'mother_is_alive' => ['label' => 'مادر در قید حیات', 'type' => 'select', 'required' => true, 'public' => false, 'options' => ['yes' => 'بله', 'no' => 'خیر']],
                 'siblings_count' => ['label' => 'تعداد خواهران و برادران', 'type' => 'number', 'required' => true, 'public' => true, 'inputmode' => 'numeric'],
                 'family_description' => ['label' => 'توضیحات بیشتر', 'type' => 'textarea', 'required' => false, 'public' => true],
            ]],
            'additional' => [ 'title' => '۳. اطلاعات جانبی', 'fields' => [
                'religious_commitment' => ['label' => 'تقید مذهبی', 'type' => 'select', 'required' => true, 'public' => true, 'options' => ['always_on_time' => 'همیشه نماز اول وقت می‌خوانند.', 'always' => 'همیشه نماز می‌خوانند اما نه اول وقت.', 'sometimes' => 'گاهی اوقات نماز می‌خوانند.', 'never' => 'نماز نمی‌خوانند.']],
                'smoker_status' => ['label' => 'مصرف کننده دخانیات', 'type' => 'select', 'required' => true, 'public' => true, 'options' => ['yes' => 'هستم', 'no' => 'نیستم']],
                // **FIXED**: Added options for military_service
                'military_service' => ['label' => 'وضعیت نظام وظیفه', 'type' => 'select', 'required' => true, 'public' => true, 'condition' => ['field' => 'gender', 'value' => 'male'], 'options' => ['conscript' => 'مشمول هستم', 'end_of_service' => 'دارای کارت پایان خدمت', 'kefalat_exemption' => 'معافیت کفالت', 'medical_exemption' => 'معافیت پزشکی', 'other_exemption' => 'معافیت سایر']],
                'marital_status' => ['label' => 'وضعیت تاهل', 'type' => 'select', 'required' => true, 'public' => true, 'options' => ['single' => 'بدون سابقه ازدواج', 'divorced' => 'متارکه کرده ام', 'widowed' => 'همسر فوت شده است.', 'martyr_spouse' => 'همسر شهید شده است.', 'engaged_divorced_not_white' => 'در دوران عقد جدا شده ام و شناسنامه سفید نیست', 'engaged_divorced_white' => 'در دوران عقد جدا شده ام و شناسنامه سفید است']],
                'has_children' => ['label' => 'دارای فرزند', 'type' => 'select', 'required' => true, 'public' => true, 'condition' => ['field' => 'marital_status', 'compare' => '!=', 'value' => 'single'], 'options' => ['yes' => 'می باشم', 'no' => 'نمی باشم']],
                'children_count' => ['label' => 'تعداد فرزند', 'type' => 'number', 'required' => true, 'public' => true, 'inputmode' => 'numeric', 'condition' => ['field' => 'has_children', 'value' => 'yes']],
                'children_description' => ['label' => 'توضیحات بیشتر', 'type' => 'textarea', 'required' => false, 'public' => true, 'condition' => ['field' => 'has_children', 'value' => 'yes'], 'description' => 'لطفا توضیحات دقیق مانند سن، وضعیت تاهل و بعد از ازدواج با شما زندگی خواهند کرد یا خیر را بنویسید.'],
            ]],
            'education' => [ 'title' => '۴. تحصیلات', 'fields' => [
                'seminary_education' => ['label' => 'تحصیلات حوزوی', 'type' => 'select', 'required' => true, 'public' => true, 'options' => ['no' => 'خیر', 'level_1' => 'مقدمات و سطح 1 حوزه علمیه', 'level_2' => 'سطح 2 حوزه علمیه', 'level_3' => 'سطح 3 حوزه علمیه', 'level_4' => 'سطح 4 و دروس خارج حوزه علمیه']],
                'education_level' => ['label' => 'سطح تحصیلات', 'type' => 'select', 'required' => true, 'public' => true, 'options' => ['under_diploma' => 'زیر دیپلم', 'diploma' => 'دیپلم', 'associate' => 'فوق دیپلم', 'bachelor' => 'کارشناسی', 'master' => 'کارشناسی ارشد', 'phd' => 'دکتری', 'postdoc' => 'فوق دکتری']],
                'education_status' => ['label' => 'وضعیت تحصیلی', 'type' => 'select', 'required' => true, 'public' => true, 'options' => ['studying' => 'در حال تحصیل (دانشجو / دانش آموز) هستم.', 'graduated' => 'اتمام تحصیل (دارای مدرک تحصیلی می باشم)']],
                'field_of_study' => ['label' => 'رشته تحصیلی', 'type' => 'text', 'required' => true, 'public' => true, 'pattern' => '^[\u0600-\u06FF\s]+$', 'validation_message' => 'لطفاً فقط از حروف فارسی استفاده کنید.'],
                'study_province' => ['label' => 'استان محل تحصیل', 'type' => 'province', 'required' => true, 'public' => true],
                'study_city' => ['label' => 'شهر محل تحصیل', 'type' => 'city', 'required' => true, 'public' => true],
                'university_name' => ['label' => 'نام دانشگاه', 'type' => 'text', 'required' => false, 'public' => true, 'pattern' => '^[\u0600-\u06FF\s]+$', 'validation_message' => 'لطفاً فقط از حروف فارسی استفاده کنید.'],
                'continue_education' => ['label' => 'آیا قصد ادامه تحصیل در مقاطع بالاتر را دارید؟', 'type' => 'select', 'required' => true, 'public' => true, 'options' => ['yes' => 'بله', 'no' => 'خیر', 'maybe' => 'شاید']],
            ]],
            'employment' => [ 'title' => '۵. وضعیت شغلی', 'fields' => [
                'employment_status' => ['label' => 'وضعیت شغلی', 'type' => 'select', 'required' => true, 'public' => true, 'options' => ['unemployed' => 'بیکار', 'employed' => 'شاغل']],
                'job_type' => ['label' => 'نوع شغل', 'type' => 'select', 'required' => true, 'public' => true, 'condition' => ['field' => 'employment_status', 'value' => 'employed'], 'options' => ['public_sector' => 'کارمند بخش دولتی', 'private_sector' => 'فعال در بخش خصوصی', 'self_employed' => 'خویش فرما، خود اشتغالی (شغل آزاد)', 'home_based' => 'در منزل کار می کنند.', 'other' => 'سایر']],
                'job_title' => ['label' => 'عنوان شغلی', 'type' => 'text', 'required' => false, 'public' => true],
                'workplace_name' => ['label' => 'نام محل کار', 'type' => 'text', 'required' => false, 'public' => true],
                'job_description' => ['label' => 'توضیحات بیشتر', 'type' => 'textarea', 'required' => false, 'public' => true],
            ]],
            'financial' => [ 'title' => '۶. وضعیت اقتصادی', 'fields' => [
                'has_house' => ['label' => 'خانه شخصی', 'type' => 'select', 'required' => true, 'public' => true, 'options' => ['yes' => 'دارم', 'no' => 'ندارم']],
                'monthly_income' => ['label' => 'متوسط درآمد ماهانه', 'type' => 'select', 'required' => true, 'public' => true, 'options' => ['none' => 'ندارم', 'under_10m' => 'زیر 10 میلیون تومان', '10_20m' => 'بین 10 الی 20 میلیون تومان', '20_50m' => 'بین 20 تا 50 میلیون تومان', '50_100m' => 'بین 50 تا 100 میلیون تومان', 'over_100m' => 'بیشتر از 100 میلیون تومان']],
                'family_financial_status' => ['label' => 'وضعیت اقتصادی خانواده', 'type' => 'select', 'required' => true, 'public' => true, 'options' => ['very_weak' => 'بسیار ضعیف', 'weak' => 'ضعیف', 'medium' => 'متوسط', 'good' => 'خوب', 'very_good' => 'بسیار خوب']],
                'financial_description' => ['label' => 'توضیحات بیشتر', 'type' => 'textarea', 'required' => false, 'public' => true]
            ]],
            'appearance' => [ 'title' => '۷. اطلاعات ظاهری', 'fields' => [
                'height' => ['label' => 'قد (سانتی‌متر)', 'type' => 'select_range', 'required' => true, 'public' => true, 'range' => range(120, 250)],
                'weight' => ['label' => 'وزن (کیلوگرم)', 'type' => 'select_range', 'required' => true, 'public' => true, 'range' => range(30, 200)],
                'skin_color' => ['label' => 'رنگ پوست', 'type' => 'select', 'required' => true, 'public' => true, 'options' => ['white' => 'سفید', 'fair' => 'گندمی روشن', 'wheat' => 'گندمی', 'tan' => 'سبزه', 'dark' => 'تیره']],
                'body_shape' => ['label' => 'تناسب اندام', 'type' => 'select', 'required' => true, 'public' => true, 'options' => ['obese' => 'چاق', 'overweight' => 'کمی اضافه وزن', 'fit' => 'متناسب', 'slim' => 'لاغر', 'very_slim' => 'خیلی لاغر']],
                'has_disease' => ['label' => 'مبتلا به بیماری خاص', 'type' => 'select', 'required' => true, 'public' => true, 'options' => ['yes' => 'بله', 'no' => 'خیر']],
                'disease_type' => ['label' => 'نوع بیماری', 'type' => 'select', 'required' => true, 'public' => false, 'condition' => ['field' => 'has_disease', 'value' => 'yes'], 'options' => [ 'limb' => 'قطع اندام فوقانی (دست) یا تحتانی (پا) یا بخش هایی از آنها', 'nervous' => 'اختلالات سیستم عصبی و ضایعات نخاعی', 'skeletal' => 'ناهنجاری های مربوط به استخوان بندی', 'cardiovascular' => 'مشکلات قلبی عروقی', 'kidney' => 'مشکلات کلیوی', 'respiratory' => 'مشکلات تنفسی', 'diabetes' => 'دیابت', 'neuro' => 'مشکلات عصبی', 'blood' => 'مشکلات خونی', 'vision' => 'مشکل در بینایی', 'hearing' => 'مشکل در شنوایی', 'facial' => 'نقص یا ایراد مشهود در چهره', 'aids_hpv' => 'ایدز / HPV', 'infertility' => 'نازایی و ناباروری', 'cancer' => 'انواع سرطان', 'other' => 'سایر' ]],
                'disease_description' => ['label' => 'توضیحات بیشتر', 'type' => 'textarea', 'required' => false, 'public' => false, 'condition' => ['field' => 'has_disease', 'value' => 'yes']],
                'has_disability' => ['label' => 'دارای معلولیت', 'type' => 'select', 'required' => true, 'public' => true, 'options' => ['yes' => 'بله', 'no' => 'خیر']],
                'disability_description' => ['label' => 'توضیحات بیشتر', 'type' => 'textarea', 'required' => false, 'public' => false, 'condition' => ['field' => 'has_disability', 'value' => 'yes']],
            ]],
            'expectations' => [ 'title' => '۸. خواسته‌ها از همسر آینده', 'fields' => [
                'partner_birth_year' => ['label' => 'متولد بین سال', 'type' => 'range_select', 'required' => true, 'public' => true, 'range' => range(1310, 1386)],
                'partner_height' => ['label' => 'قد همسر (سانتی متر)', 'type' => 'range_select', 'required' => true, 'public' => true, 'range' => range(120, 250)],
                'partner_weight' => ['label' => 'وزن همسر (کیلوگرم)', 'type' => 'range_select', 'required' => true, 'public' => true, 'range' => range(30, 200)],
                'partner_marital_status' => ['label' => 'وضعیت تاهل همسر مورد نظر', 'type' => 'select', 'required' => true, 'public' => true, 'options' => ['any' => 'فرقی نمی‌کند', 'single' => 'بدون سابقه ازدواج', 'divorced' => 'متارکه کرده باشد', 'widowed' => 'همسر فوت شده باشد', 'martyr_spouse' => 'همسر شهید شده باشد', 'engaged_divorced_not_white' => 'در دوران عقد جدا شده باشد و شناسنامه سفید نباشد', 'engaged_divorced_white' => 'در دوران عقد جدا شده باشد و شناسنامه سفید باشد']],
                'partner_children_acceptance' => ['label' => 'فرزند فرد مقابل', 'type' => 'select', 'required' => true, 'public' => true, 'options' => ['accept' => 'می پذیرم', 'reject' => 'نمی پذیرم']],
                'partner_description' => ['label' => 'توضیحات بیشتر', 'type' => 'textarea', 'required' => false, 'public' => true],
            ]],
            'contact' => [ 'title' => '۹. اطلاعات تماس', 'fields' => [
                'landline_phone' => ['label' => 'تلفن ثابت', 'type' => 'tel', 'required' => true, 'public' => false, 'pattern' => '^0[0-9]{10}$', 'inputmode' => 'numeric', 'validation_message' => 'فرمت تلفن ثابت صحیح نیست (مثال: 02112345678).'],
                'residence_province' => ['label' => 'استان محل زندگی', 'type' => 'province', 'required' => true, 'public' => true],
                'residence_city' => ['label' => 'شهر محل زندگی', 'type' => 'city', 'required' => true, 'public' => true],
                'postal_code' => ['label' => 'کد پستی', 'type' => 'tel', 'required' => true, 'public' => false, 'pattern' => '^[0-9]{10}$', 'inputmode' => 'numeric', 'validation_message' => 'کد پستی باید ۱۰ رقم باشد.'],
                'address' => ['label' => 'نشانی محل اقامت', 'type' => 'textarea', 'required' => true, 'public' => false],
            ]],
            'documents' => [ 'title' => '۱۰. ارسال مدارک', 'fields' => [
                'doc_id_page1' => ['label' => 'صفحه اول شناسنامه', 'type' => 'file', 'required' => true, 'public' => false],
                'doc_id_marriage' => ['label' => 'صفحه ازدواج و طلاق شناسنامه', 'type' => 'file', 'required' => true, 'public' => false],
                'doc_id_children' => ['label' => 'صفحه فرزندان شناسنامه', 'type' => 'file', 'required' => true, 'public' => false],
                'doc_id_desc' => ['label' => 'صفحه توضیحات شناسنامه', 'type' => 'file', 'required' => true, 'public' => false],
                'doc_national_card' => ['label' => 'تصویر کارت ملی', 'type' => 'file', 'required' => true, 'public' => false],
                'doc_profile_pic' => ['label' => 'عکس چهره', 'type' => 'file', 'required' => true, 'public' => false, 'description' => 'در سایت نمایش داده نمی شود و برای احراز هویت فقط استفاده می شود. بدون عینک، کلاه و از رو به رو.'],
            ]],
        ];
    }
}
