<h3><?= lang('auth.email_validation_subject'); ?></h3>

<p><?= lang('auth.email_validation_message'); ?></p>
<p><?= anchor('auth/validate/' . $user->id . '/' . $user->validate_hash); ?></p>
