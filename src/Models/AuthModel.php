<?php

namespace jellelampaert\ci4_auth\Models;

use CodeIgniter\Model;

class AuthModel extends Model
{
    private $error = '';
    protected $table = 'users';

    public function __construct()
    {
        parent::__construct();
        
        $this->config = config('Auth');
        $this->session = session();
    }

    public function activateUser($id)
    {
        $this->db->table($this->table)->where('id', $id)->update(array(
            'active'    => 1
        ));
    }

    public function addRole($name)
    {
        $this->db->table('auth_role')->insert(array(
            'name'  => $name
        ));
    }

    /*
     * Add a user, do not check if a user can register.
     * Can be used when an admin wants to create a user
     */
    public function addUser($email, $password)
    {
        // Is the e-mail address unique?
        $user = $this->getUserByEmail($email);
        if ($user) {
            $this->error = lang('auth.user_already_exists');
            return false;
        }

        $request = \Config\Services::request();

        $this->db->table($this->table)->insert(array(
            'email'         => $email,
            'password'      => $this->hashPassword($password),
            'active'        => $this->config->newUserIsActive,
            'create_ip'     => $request->getIPAddress(),
            'created_at'    => date('Y-m-d H:i:s', time()),
            'validated'     => !$this->config->newUserMustValidate,
            'role'          => $this->config->defaultUserRole
        ));

        $user_id = $this->db->insertID();

        \CodeIgniter\Events\Events::trigger('user_created', $user_id);

        return $user_id;
    }

    public function changePassword($id, $password)
    {
        $this->db->table($this->table)->where('id', $id)->update(array(
            'must_change_pwd'   => 0,
            'password'          => $this->hashPassword($password),
            'updated_at'        => date('Y-m-d H:i:s', time())
        ));
    }

    public function checkResetHash($id, $hash)
    {
        $user = $this->getUserById($id);

        if (!$user) {
            return false;
        }
        
        if (strtotime($user->reset_hash_valid_until) < time()) {
            return false;
        }

        if ($user->reset_hash != $hash) {
            return false;
        }

        return true;
    }

    public function clearResetHash($id)
    {
        $this->db->table($this->table)->where('id', $id)->update(array(
            'reset_hash_valid_until' => date('Y-m-d H:i:s', time() - 1)
        ));
    }

    public function createResetHash($id)
    {
        $hash = bin2hex(random_bytes(24));
        $this->db->table($this->table)->where('id', $id)->update(array(
            'reset_hash'                => $hash,
            'reset_hash_valid_until'    => date('Y-m-d H:i:s', time() + $this->config->resetExpire)
        ));
        
        \CodeIgniter\Events\Events::trigger('user_reset_hash_created', $id);

        return $hash;
    }

    public function createValidationHash($id = false)
    {
        $hash = bin2hex(random_bytes(24));
        $this->db->table($this->table)->where('id', $id)->update(array(
            'validate_hash' => $hash
        ));

        return $hash;
    }

    public function deactivateUser($id)
    {
        $this->db->table($this->table)->where('user_id', $id)->update(array(
            'active'    => 0
        ));
    }

    public function deleteUser($id)
    {
        $this->db->table($this->table)->where('id', $id)->delete();
    }

    /*
     * Log a user in
     */
    public function doLogin($email, $password, $remember = 0)
    {
        // Does the user exist?
        $user = $this->getUserByEmail($email);
        if (!$user) {
            $this->error = lang('auth.user_not_found');
            $this->logLoginAttempt($email, 0, 0, 'user_not_found');

            return false;
        }

        // Is the password correct?
        $correct = password_verify(base64_encode(hash('sha384', $password, true)), $user->password);

        if (!$correct) {
            // Password incorrect
            $this->error = lang('auth.bad_password');
            $this->logLoginAttempt($email, $user->id, 0, 'bad_password');
            return false;
        }

        // Do we need to rehash the password?
        if (password_needs_rehash($user->password, $this->config->hashAlgorithm)) {
            // Password needs a rehash ==> Algorithm has probably changed
            $this->db->table($this->table)->where('id', $user->id)->update(array(
                'password'  => $this->hashPassword($password)
            ));
        }

        // Is the user active?
        if (!$user->active) {
            $this->error = lang('auth.user_inactive');
            $this->logLoginAttempt($email, $user->id, 0, 'user_inactive');

            return false;
        }

        // Is the user validated?
        if (!$user->validated) {
            $this->error = lang('auth.user_not_validated');
            $this->logLoginAttempt($email, $user->id, 0, 'user_not_validated');

            return false;
        }

        // Log the login attempt
        $this->logLoginAttempt($email, $user->id, 1);

        // Set the session
        session()->set('logged_in', $user->id);

        // Remember the user?
        if ($remember) {
            // Can we remember the user?
            if ($this->config->allowRemember) {
                $this->rememberUser($user->id);
            }
        }

        \CodeIgniter\Events\Events::trigger('login', $user->id);

        return true;
    }
    
    public function getError()
    {
        return $this->error;
    }

    public function getUserByEmail($email)
    {
        return $this->db->table($this->table)->where('email', $email)->get()->getRow();
    }

    public function getUserById($id)
    {
        return $this->db->table($this->table)->where('id', $id)->get()->getRow();
    }

    /*
     * Implement a secure password hash
     * https://paragonie.com/blog/2015/04/secure-authentication-php-with-long-term-persistence
     */
    private function hashPassword($password)
    {
        return password_hash(base64_encode(hash('sha384', $password, true)), $this->config->hashAlgorithm);
    }

    /*
     * Check if a user is logged in
     */
    public function isLoggedIn()
    {
        $user_id = 0;

        // Is there a session?
        if (!session('logged_in')) {
            // No session, is remembering the user allowed?
            if ($this->config->allowRemember) {
                // check if there's a cookie
                helper('cookie');
                $remember = get_cookie('remember');
                if (empty($remember)) {
                    // There's no cookie.
                    return false;
                }

                // Cookie found. Check it.
                [$selector, $validator] = explode(':', $remember);
        
                $row = $this->db->table('auth_login_sessions')->where('selector', $selector)->get()->getRow();
                if (!$row) {
                    // This selector was not found in the sessions-table
                    return false;
                }

                // There is a valid selector. Check the date
                $valid_until = strtotime($row->expires);
                if ($valid_until < time()) {
                    // Cookie not valid anymore
                    // Purge old sessions
                    $this->purge_old_sessions();
                    return false;
                }
                // Check the validator
                if (!hash_equals($row->validator, hash('sha256', $validator))) {
                    // Validater hash failed.
                    return false;
                }

                // Cookie ok, set the user_id-variable and the session
                $user_id = $row->user_id;
                session()->set('logged_in', $user_id);

                // Refresh the hash
                $validator = bin2hex(random_bytes(24));
                $expires = date('Y-m-d H:i:s', time() + $this->config->rememberExpire);
    
                $request = \Config\Services::request();
                $this->db->table('auth_login_sessions')->where('selector', $selector)->update(array(
                    'validator' => hash('sha256', $validator),
                    'expires'   => $expires,
                    'ip'        => $request->getIPAddress()
                ));
    
                // Refresh the cookie
                $token = $selector . ':' . $validator;
                $app_config = config('App');
                helper('cookie');
                set_cookie(
                    'remember',
                    $token,
                    $this->config->rememberExpire,
                    $app_config->cookieDomain,
                    $app_config->cookiePath,
                    $app_config->cookiePrefix,
                    $app_config->cookieHTTPOnly,
                    true
                );
            } else {
                // Delete the cookie
                $this->logout();
                return false;
            }

        } else {
            $user_id = session('logged_in');
        }
        
        $user = $this->getUserById($user_id);
        if (!$user) {
            // User doesn't exist anymore
            return false;
        }

        if (!$user->active) {
            $this->error = lang('auth.user_inactive');
            return false;
        }
        
        return $user;
    }

    private function logLoginAttempt($email, $id = 0, $success = 0, $reason = '')
    {
        // Load the request-info
        $request = \Config\Services::request();

        // Record the login-attempt
        $this->db->table('auth_login_attempts')->insert(array(
            'ip'            => $request->getIPAddress(),
            'email'         => $email,
            'user_id'       => $id,
            'date'          => date('Y-m-d H:i:s', time()),
            'success'       => $success,
            'user_agent'    => $request->getUserAgent(),
            'reason'        => $reason
        ));
    }

    public function logout()
    {
        $logged_in = $this->isLoggedIn();
        
        if ($logged_in) {
            session()->remove('logged_in');
            $app_config = config('App');
            helper('cookie');
            delete_cookie(
                'remember',
                $app_config->cookieDomain,
                $app_config->cookiePath,
                $app_config->cookiePrefix
            );

            \CodeIgniter\Events\Events::trigger('logout', $logged_in->id);
        }
    }

    private function purgeOldSessions()
    {
        $this->db->table('auth_login_sessions')->where('expires < NOW()')->delete();
    }

    /*
     * Register a new user
     */
    public function registerUser($email, $password)
    {
        // Can we register a new user?
        if (!$this->config->userCanRegister) {
            $this->error = lang('auth.registration_disabled');
            return false;
        }

        // Add the user
        $user_id = $this->addUser($email, $password);
        \CodeIgniter\Events\Events::trigger('user_registered', $user_id);

        // Must the user be activated by an admin?
        if (!$this->config->newUserIsActive) {
            $this->deactivateUser($user_id);

            \CodeIgniter\Events\Events::trigger('user_must_be_activated', $user_id);
        }

        // Must the user validate it's e-mail address?
        if ($this->config->newUserMustValidate) {
            // Creat a validation hash for the user
            $this->createValidationHash($user_id);

            // Trigger the appropriate event
            \CodeIgniter\Events\Events::trigger('user_must_be_validated', $user_id);
        }

        // Return the userID for the new user
        return $user_id;
    }

    private function rememberUser($user_id)
    {
        // Remember me function, see: https://paragonie.com/blog/2015/04/secure-authentication-php-with-long-term-persistence

        // Create some truly random strings
        $selector = bin2hex(random_bytes(16));
        $validator = bin2hex(random_bytes(24));
        $expires = date('Y-m-d H:i:s', time() + $this->config->rememberExpire);

        // Save the data in the database
        $request = \Config\Services::request();
        $this->db->table('auth_login_sessions')->insert(array(
            'selector'  => $selector,
            'validator' => hash('sha256', $validator),
            'user_id'   => $user_id,
            'expires'   => $expires,
            'ip'        => $request->getIPAddress()
        ));

        // Save a cookie
        $token = $selector . ':' . $validator;
        $app_config = config('App');
        helper('cookie');
        set_cookie(
            'remember',
            $token,
            time() + $this->config->rememberExpire,
            $app_config->cookieDomain,
            $app_config->cookiePath,
            $app_config->cookiePrefix,
            $app_config->cookieHTTPOnly,
            true
        );
    }

    public function resendValidation($email)
    {
        $user = $this->getUserByEmail($email);
        if (!$user) {
            return false;
        }

        \CodeIgniter\Events\Events::trigger('user_must_be_validated', $user->id);
        return true;
    }

    public function validateUser($id, $hash)
    {
        if (!is_numeric($id)) {
            return false;
        }

        $user = $this->getUserById($id);

        if (!$user) {
            return false;
        }

        if ($user->validate_hash != $hash) {
            return false;
        }

        $this->db->table($this->table)->where('id', $id)->update(array(
            'validated' => 1
        ));
        return true;
    }
}