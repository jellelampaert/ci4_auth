<h3><?= lang('auth.email_reset_password_subject'); ?></h3>

<p><?= lang('auth.email_reset_password_message'); ?></p>
<p><?= anchor('auth/reset_password/' . $user->id . '/' . $user->reset_hash); ?></p>
