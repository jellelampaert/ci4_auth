<?= $this->extend($config->layoutPage) ?>
<?= $this->section('content') ?>

<div class="block wrapper">
    <h3><?= lang('auth.register_title'); ?></h3>
    <form method="post" action="<?= route_to('auth/register'); ?>">
        <p><label for="email"><?= lang('auth.email'); ?>: </label><input type="text" name="email" id="email" value="<?= old('email'); ?>" /></p>
        <p><label for="password"><?= lang('auth.password'); ?>: </label><input type="password" name="password" id="password"></p>
        <p><label></label><input type="submit" value="<?= lang('auth.btn_register'); ?>" name="btnSubmit" /></p>
    </form>
</div>
<script type="text/javascript">
document.getElementById('email').focus();
</script>

<?= $this->endSection() ?>