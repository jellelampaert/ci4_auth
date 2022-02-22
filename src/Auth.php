<?php

namespace jellelampaert\ci4_auth;

use jellelampaert\ci4_auth\Models\AuthModel;

class Auth
{
    private $model;

    public function __construct()
    {
        $this->model = new AuthModel();
    }

    /**
     * Check if the user is logged in
     *
     * @return bool
     */
    public function isLoggedIn()
    {
        return $this->model->isLoggedIn() ? true : false;
    }

    /**
     * Log a user out
     */
    public function logout()
    {
        $this->model->logout();
    }

    /**
     * Get the logged in user
     *
     * @return object|null
     */
    public function user()
    {
        $user = $this->model->isLoggedIn();
        if ($user) {
            return $user;
        }

        return null;
    }

    /**
     * Get the user-id of the logged in user
     *
     * @return int|null
     */
    public function user_id()
    {
        $user = $this->model->isLoggedIn();
        if ($user) {
            return $user->id;
        }

        return null;
    }
}