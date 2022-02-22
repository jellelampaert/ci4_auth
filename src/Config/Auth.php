<?php namespace jellelampaert\ci4_auth\Config;

use CodeIgniter\Config\BaseConfig;

class Auth extends BaseConfig
{
    /*
     * Can a user register itself?
     */
    public $userCanRegister = true;

    /*
     * Is a new user activated automatically or does an admin need to activate the account first?
     */
    public $newUserIsActive = true;

    /*
     * Does a new user need to validate it's e-mail address?
     */
    public $newUserMustValidate = true;

    /*
     * What's the default user role?
     */
    public $defaultUserRole = 1;

    /*
     * Which hashing algorithm do we need to use
     */
    public $hashAlgorithm = PASSWORD_DEFAULT;

    /*
     * Allow remembering the login-session?
     */
    public $allowRemember = true;

    /*
     * How long should we remember someone in seconds?
     */
    public $rememberExpire = 604800;

    /*
     * How long should a password reset hash be valid (in seconds)?
     */
    public $resetExpire = 43200;

    /*
     * Set a general layout-page
     */
    public $layoutPage = 'jellelampaert\ci4_auth\Views\layout';

    /*
     * Set the different views
     */
    public $views = array(
        'forgot'            => 'jellelampaert\ci4_auth\Views\forgot_password',
        'login'             => 'jellelampaert\ci4_auth\Views\login',
        'pwd_change'        => 'jellelampaert\ci4_auth\Views\pwd_change',
        'register'          => 'jellelampaert\ci4_auth\Views\register',
        'resend_validation' => 'jellelampaert\ci4_auth\Views\resend_validation',
        'reset_password'    => 'jellelampaert\ci4_auth\Views\reset_password'
    );

    /*
     * Does this package needs to send mails or not?
     */
    public $packageMustSendMails = true;

    /*
     * If the package needs to send e-mails,
     * what should be the from-address
     */
    public $mailFrom = 'noreply@example.com';

    /*
     * Set the mail templates
     */
    public $mails = array(
        'validate'          => 'jellelampaert\ci4_auth\Views\mails\validate_email',
        'reset_password'    => 'jellelampaert\ci4_auth\Views\mails\reset_password'
    );
}
