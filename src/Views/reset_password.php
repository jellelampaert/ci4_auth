<?= $this->extend($config->layoutPage) ?>
<?= $this->section('content') ?>

<div class="block wrapper">
    <h3><?= lang('auth.change_password'); ?></h3>
    <form method="post" action="<?= route_to('do_reset_password', $id, $hash); ?>">
        <p><label for="password"><?= lang('auth.password'); ?>: </label><input type="password" name="password" id="password" /></p>
        <p><label for="password2"><?= lang('auth.repeat_password'); ?>: </label><input type="password" name="password2" id="password2" /></p>
        <p><label></label><input type="submit" value="<?= lang('auth.change_password'); ?>" name="btnSubmit" /></p>
    </form>
</div>

<?= $this->endSection() ?>