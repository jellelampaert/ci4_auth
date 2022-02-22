<?= $this->extend($config->layoutPage) ?>
<?= $this->section('content') ?>

<div class="block wrapper">
    <h3><?= lang('auth.resend_validation'); ?></h3>
    <form method="post" action="<?= route_to('do_resend_validation'); ?>">
        <p><label for="email"><?= lang('auth.email'); ?>: </label><input type="text" name="email" id="email" value="<?= old('email'); ?>" /></p>
        <p><label></label><input type="submit" value="<?= lang('auth.btn_resend'); ?>" name="btnSubmit" /></p>
    </form>
</div>

<?= $this->endSection() ?>