# Autentication and authorization-system for CodeIgniter 4

## Configuration
Configuration is done in `Config/Auth.php`, or in the `.env`-file.

## Events
There are certain events you can subscribe to in your `Config/Events.php`.
* _login($user_id)_ - A user has logged in
* _logout($user_id)_ - A user has logged out
* _user_created($user_id)_ - A new user was created, either by using the registration form or in code.
* _user_registered($user_id)_ - A new user has registered by using the registration form
* _user_must_be_activated($user_id)_ - Called when a new users has been created, but an admin must activate the user
* _user_must_be_validated($user_id)_ - Called whenever a new validation-hash is created, e.g. when a user is created and must be validated or when a user's validation hash was reset (due to hash timeout)
* _user_reset_hash_created($user_id)_ - Called whenever a password reset hash has been created

## FAQ
*How can I check if a user is logged in?*  
You can check if a user is logged in, by implementing a filter for the pages you need protected.
In *Config/Filters.php*, add following to the aliasses:
    `'auth' 	   => \jellelampaert\ci4_auth\Filters\Auth::class`
Next, add a filter for the protected pages, e.g.:
    `public $filters = [
		'auth' => ['before' => ['admin', 'admin/*']]
	];`