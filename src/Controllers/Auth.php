<?php

namespace jellelampaert\ci4_auth\Controllers;

use CodeIgniter\Controller;
use jellelampaert\ci4_auth\Models\AuthModel;

class Auth extends Controller
{

    public function __construct()
    {
        $this->config = config('Auth');
    }

    public function doForgotPassword()
    {
        // Check the fields
        $rules = [
            'email'         => 'required|valid_email',
        ];
        if (!$this->validate($rules)) {
            return redirect()->back()->withInput()->with('error', $this->validator->getErrors());
        }

        $auth = new AuthModel();

        $user = $auth->getUserByEmail($this->request->getVar('email'));

        if (!$user) {
            // User not found
            return redirect()->back()->withInput()->with('error', lang('auth.user_not_found'));
        }

        $auth->createResetHash($user->id);

        return redirect()->route('login')->with('success', lang('auth.password_reset_sent'));
    }

    public function doLogin()
    {
        $auth = new AuthModel();

        // Check the user's credentials
        $user_id = $auth->doLogin($this->request->getVar('email'), $this->request->getVar('password'), !empty($this->request->getVar('remember')));

        if (!$user_id) {
            // Bad password
            return redirect()->back()->withInput()->with('error', $auth->getError());
        }

        // Where to redirect after login?
        $redirect_to = session('redirect_url') ?? '/';

        return redirect()->to($redirect_to)->withCookies()->with('success', lang('auth.login_success'));
    }

    public function doPwdChange()
    {
        $auth = new AuthModel();

        $user = $auth->isLoggedIn();
        if (!$user) {
            // Not logged in ==> Can't do a password change
            return redirect()->route('login');
        }

        // Check the fields
        $rules = [
            'password'      => 'required|min_length[5]',
            'password2'     => 'required|min_length[5]|matches[password]',
        ];
        if (!$this->validate($rules)) {
            return redirect()->route('pwd_change')->withInput()->with('error', $this->validator->getErrors());
        }

        $auth->changePassword($user->id, $this->request->getVar('password'));

        $redirect_to = session('redirect_url') ?? '/';

        return redirect()->to($redirect_to)->withCookies()->with('success', lang('auth.password_changed'));
    }

    public function doRegister()
    {
        // Can the user register?
        if (!$this->config->userCanRegister) {
            return redirect()->to('/')->with('error', lang('auth.registration_disabled'));
        }

        // Check the fields
        $rules = [
            'email'         => 'required|valid_email',
            'password'      => 'required',
        ];
        if (!$this->validate($rules)) {
            return redirect()->back()->withInput()->with('error', $this->validator->getErrors());
        }

        $auth = new AuthModel();

        // Create the user
        $user_id = $auth->registerUser(
            $this->request->getVar('email'),
            $this->request->getVar('password')
        );

        if (!$user_id) {
            // Something went wrong.
            return redirect()->back()->withInput()->with('error', $auth->getError());
        }

        return redirect()->route('login')->with('success', lang('auth.user_created'));
    }

    public function doResendValidation()
    {
        // Check the fields
        $rules = [
            'email'         => 'required|valid_email',
        ];
        if (!$this->validate($rules)) {
            return redirect()->back()->withInput()->with('error', $this->validator->getErrors());
        }

        $auth = new AuthModel();
        $auth->resendValidation($this->request->getVar('email'));

        return redirect()->route('login')->with('success', lang('auth.validation_sent'));
    }

    public function doResetPassword($id, $hash)
    {
        $authModel = new AuthModel();

        if (!$authModel->checkResetHash($id, $hash)) {
            return redirect()->back()->with('error', lang('auth.password_reset_failed'));
        }

        // Check the fields
        $rules = [
            'password'      => 'required|min_length[5]',
            'password2'     => 'required|min_length[5]|matches[password]',
        ];
        if (!$this->validate($rules)) {
            return redirect()->back()->with('error', $this->validator->getErrors());
        }

        $authModel->changePassword($id, $this->request->getVar('password'));
        $authModel->clearResetHash($id);

        return redirect()->route('login')->with('success', lang('auth.password_changed'));
    }

    public function forgotPassword()
    {
        return view($this->config->views['forgot'], ['config' => $this->config]);
    }

    public function login()
    {
        return view($this->config->views['login'], ['config' => $this->config]);
    }

    public function logout()
    {
        $auth = new AuthModel();
        $auth->logout();

        $redirect_to = session('redirect_url') ?? '/';
        return redirect()->to($redirect_to)->withCookies()->with('success', lang('auth.logout_success'));
    }

    public function pwdChange()
    {
        $auth = new AuthModel();
        if ($user = $auth->isLoggedIn()) {
            return view($this->config->views['pwd_change'], array(
                'config'    => $this->config,
                'user'      => $user
            ));
        }

        return redirect()->route('login');
    }

    public function register()
    {
        if (!$this->config->userCanRegister) {
            return redirect()->to('/')->with('error', lang('auth.registration_disabled'));
        }

        return view($this->config->views['register'], ['config' => $this->config]);
    }

    public function resendValidation()
    {
        return view($this->config->views['resend_validation'], ['config' => $this->config]);
    }

    public function resetPassword($id, $hash)
    {
        $authModel = new AuthModel();

        if (!$authModel->checkResetHash($id, $hash)) {
            return redirect()->route('login')->withCookies()->with('error', lang('auth.password_reset_failed'));
        }

        return view($this->config->views['reset_password'], array(
            'id'    => $id,
            'hash'  => $hash,
            'config'=> $this->config
        ));
    }

    public function validateUser($id, $hash)
    {
        $authModel = new AuthModel();

        if ($authModel->validateUser($id, $hash)) {
            return redirect()->route('login')->with('success', lang('auth.user_validated'));
        } else {
            return redirect()->route('login')->with('error', lang('auth.invalid_validate_url'));
        }
    }

}