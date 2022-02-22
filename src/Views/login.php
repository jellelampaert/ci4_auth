<?= $this->extend($config->layoutPage) ?>
<?= $this->section('content') ?>

<div class="block wrapper">
    <h3><?= lang('auth.login_title'); ?></h3>
    <form method="post" action="<?= route_to('auth/do_login'); ?>">
        <p><label for="email"><?= lang('auth.email'); ?>: </label><input type="text" name="email" id="email" value="<?= old('email'); ?>" /></p>
        <p><label for="password"><?= lang('auth.password'); ?>: </label><input type="password" name="password" id="password" /></p>
        <p><label for="remember"><?= lang('auth.remember_me'); ?>: </label><input type="checkbox" name="remember" id="remember" /></p>
        <p><label></label><input type="submit" value="<?= lang('auth.btn_login'); ?>" name="btnSubmit" /></p>
    </form>
</div>
<script type="text/javascript">
document.getElementById('email').focus();
</script>

<?= $this->endSection() ?>