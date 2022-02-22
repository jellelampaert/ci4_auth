<?php

if (! function_exists('logged_in'))
{
    /**
     * Check if the user is logged in
     *
     * @return bool
     */
    function logged_in()
    {
        $auth = new jellelampaert\ci4_auth\Auth();
        return $auth->isLoggedIn();
    }
}

if (! function_exists('user'))
{
    /**
     * Returns the currently logged in user
     *
     * @return object|null
     */
    function user()
    {
        $auth = new jellelampaert\ci4_auth\Auth();
        return $auth->user();
    }
}

if (! function_exists('user_id'))
{
    /**
     * Returns the user_id of the currently logged in user
     *
     * @return int|null
     */
    function user_id()
    {
        $auth = new jellelampaert\ci4_auth\Auth();
        return $auth->user_id();
    }
}