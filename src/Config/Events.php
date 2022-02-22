<?php

namespace jellelampaert\ci4_auth\Config;

use CodeIgniter\Events\Events;

Events::on('user_must_be_validated', function($user_id) {
    $config = config('Auth');
    if ($config->packageMustSendMails) {
        $auth = new \jellelampaert\ci4_auth\Models\AuthModel();
        $user = $auth->getUserById($user_id);

        if ($user) {
            $email = \Config\Services::email();

            $mailconfig = array();
            $mailconfig['mailType'] = 'html';
            $email->initialize($mailconfig);
    
            $email->setFrom($config->mailFrom);
            $email->setTo($user->email);
    
            $email->setSubject(lang('auth.email_validation_subject'));
            $email->setMessage(view($config->mails['validate'], ['user' => $user]));
    
            $email->send();
        }
    }
});

Events::on('user_reset_hash_created', function($user_id) {
    $config = config('Auth');
    if ($config->packageMustSendMails) {
        $auth = new \jellelampaert\ci4_auth\Models\AuthModel();
        $user = $auth->getUserById($user_id);

        if ($user) {
            $email = \Config\Services::email();

            $mailconfig = array();
            $mailconfig['mailType'] = 'html';
            $email->initialize($mailconfig);
    
            $email->setFrom($config->mailFrom);
            $email->setTo($user->email);
    
            $email->setSubject(lang('auth.email_reset_password_subject'));
            $email->setMessage(view($config->mails['reset_password'], ['user' => $user]));
    
            $email->send();
        }
    }
});
