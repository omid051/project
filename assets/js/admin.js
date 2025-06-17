jQuery(document).ready(function($) {
    'use strict';
    const reviewBox = $('#hs-admin-review-box');
    if (!reviewBox.length) { return; }
    
    const actionsWrapper = reviewBox.find('.hs-admin-actions');
    const approveBtn = $('#hs-approve-btn');
    const rejectPromptBtn = $('#hs-reject-btn-prompt');
    const rejectConfirmBtn = $('#hs-reject-btn-confirm');
    const rejectCancelBtn = $('#hs-reject-cancel-btn');
    const rejectionWrapper = $('#rejection-reason-wrapper');
    const rejectionTextarea = $('#rejection_reason');
    const messageDiv = $('#hs-action-message');
    const spinner = actionsWrapper.find('.spinner');

    approveBtn.on('click', function() {
        if (!confirm('آیا از تأیید این کاربر اطمینان دارید؟ نقش او به «تأیید شده» تغییر خواهد کرد.')) { return; }
        performAction('hs_approve_user', $(this).data('user-id'));
    });

    rejectPromptBtn.on('click', function() {
        rejectionWrapper.slideDown();
        approveBtn.hide();
        rejectPromptBtn.hide();
    });

    rejectCancelBtn.on('click', function() {
        rejectionWrapper.slideUp();
        rejectionTextarea.val('');
        approveBtn.show();
        rejectPromptBtn.show();
    });

    rejectConfirmBtn.on('click', function() {
        const reason = rejectionTextarea.val();
        if (!reason.trim()) {
            alert('لطفاً دلیل رد پروفایل را وارد کنید.');
            rejectionTextarea.focus();
            return;
        }
        performAction('hs_reject_user', $(this).data('user-id'), { reason: reason });
    });

    function performAction(action, userId, additionalData = {}) {
        spinner.addClass('is-active');
        actionsWrapper.find('button').prop('disabled', true);
        const data = { action: action, _ajax_nonce: hs_admin_data.nonce, user_id: userId, ...additionalData };

        $.post(ajaxurl, data)
            .done(function(response) {
                if (response.success) {
                    showMessage(response.data.message, 'success');
                    actionsWrapper.find('button').hide();
                    rejectionWrapper.hide();
                } else {
                    showMessage(response.data.message || 'یک خطای ناشناخته رخ داد.', 'error');
                    actionsWrapper.find('button').prop('disabled', false);
                }
            })
            .fail(function() { showMessage('خطای سرور. لطفاً دوباره تلاش کنید.', 'error'); actionsWrapper.find('button').prop('disabled', false); })
            .always(function() { spinner.removeClass('is-active'); });
    }

    function showMessage(message, type) {
        messageDiv.text(message).removeClass('notice-success notice-error').addClass(type === 'success' ? 'notice-success' : 'notice-error').slideDown();
    }
});