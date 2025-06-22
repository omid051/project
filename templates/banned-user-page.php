<?php
/**
 * Template for displaying the banned user notice.
 *
 * @var string $remaining_time The human-readable time remaining for the ban.
 */
if (!defined('ABSPATH')) {
    exit;
}
?>
<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
    <meta charset="<?php bloginfo('charset'); ?>">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>دسترسی مسدود شده</title>
    <?php wp_head(); ?>
    <style>
        body {
            background-color: #f0f0f1;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
        }
        .hs-banned-container {
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background-color: #fff;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            text-align: center;
            width: 90%;
            max-width: 500px;
        }
        .hs-banned-container h1 {
            font-size: 24px;
            color: #dc3232;
            margin-bottom: 15px;
        }
        .hs-banned-container p {
            font-size: 16px;
            color: #444;
            line-height: 1.6;
        }
        .hs-banned-container .remaining-time {
            display: block;
            font-size: 20px;
            font-weight: bold;
            color: #1d2327;
            margin-top: 20px;
            direction: rtl;
        }
        .hs-banned-container a {
            margin-top: 25px;
            display: inline-block;
            font-size: 14px;
        }
    </style>
</head>
<body <?php body_class(); ?>>
    <div class="hs-banned-container">
        <h1>دسترسی شما مسدود شده است</h1>
        <p>بنا به تشخیص مدیریت، حساب کاربری شما به صورت موقت از دسترس خارج شده است.</p>
        <p>زمان باقی‌مانده تا رفع محدودیت:</p>
        <div class="remaining-time"><?php echo esc_html($remaining_time); ?></div>
        <a href="<?php echo esc_url(wp_logout_url(home_url())); ?>">خروج از حساب کاربری</a>
    </div>
    <?php wp_footer(); ?>
</body>
</html>
