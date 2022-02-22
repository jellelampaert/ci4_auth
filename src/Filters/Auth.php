<?php namespace jellelampaert\ci4_auth\Filters;

use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use CodeIgniter\Filters\FilterInterface;

class Auth implements FilterInterface
{
    public function before(RequestInterface $request, $arguments = null)
    {
        $auth = new \jellelampaert\ci4_auth\Models\AuthModel();

        $user = $auth->isLoggedIn();
        if (!$user) {
            $_SESSION['redirect_url'] = current_url();
            return redirect()->route('login');
        }

        if ($user->must_change_pwd) {
            $_SESSION['redirect_url'] = current_url();
            return redirect()->route('pwd_change');
        }
    }

    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
    }
}