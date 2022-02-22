<?php

/**
 * jellelampaert:ci4_auth routes file.
 */

$routes->group('auth', ['namespace' => 'jellelampaert\ci4_auth\Controllers'], function($routes) {    
    $routes->get('', 'Auth::login');

    // Login/out
    $routes->get('login', 'Auth::login', ['as' => 'login']);
    $routes->post('login', 'Auth::doLogin');
    $routes->get('logout', 'Auth::logout');
    $routes->get('pwd_change', 'Auth::pwdChange', ['as' => 'pwd_change']);
    $routes->post('pwd_change', 'Auth::doPwdChange', ['as' => 'do_pwd_change']);

    // Registration
    $routes->get('register', 'Auth::register', ['as' => 'register']);
    $routes->post('register', 'Auth::doRegister');

    // Activation / validation
    $routes->get('validate/(:num)/(:any)', 'Auth::validateUser/$1/$2', ['as' => 'activate']);
    $routes->get('resend_validation', 'Auth::resendValidation', ['as' => 'resend_validation']);
    $routes->post('resend_validation', 'Auth::doResendValidation', ['as' => 'do_resend_validation']);

    // Forgot/Resets
    $routes->get('forgot', 'Auth::forgotPassword', ['as' => 'forgot']);
    $routes->post('forgot', 'Auth::doForgotPassword');
    $routes->get('reset_password/(:num)/(:any)', 'Auth::resetPassword/$1/$2', ['as' => 'reset_password']);
    $routes->post('reset_password/(:num)/(:any)', 'Auth::doResetPassword/$1/$2', ['as' => 'do_reset_password']);
});