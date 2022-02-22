<?php namespace jellelampaert\ci4_auth\Database\Migrations;

use CodeIgniter\Database\Migration;

class Authentication_tables extends Migration
{
    public function up()
    {
        /*
         * Users
         */
        $this->forge->addField([
            'id'                        => ['type' => 'int', 'constraint' => 11, 'unsigned' => true, 'auto_increment' => true],
            'email'                     => ['type' => 'varchar', 'constraint' => 255],
            'name'                      => ['type' => 'varchar', 'constraint' => 50],
            'password'                  => ['type' => 'varchar', 'constraint' => 255],
            'role'                      => ['type' => 'int', 'unsigned' => true, 'default' => 1],
            'active'                    => ['type' => 'boolean', 'default' => 0],
            'create_ip'                 => ['type' => 'varchar', 'constraint' => 46],   // User created from IP
            'created_at'                => ['type' => 'datetime', 'null' => true],      // User create time
            'updated_at'                => ['type' => 'datetime', 'null' => true],      // User updated at
            'must_change_pwd'           => ['type' => 'boolean', 'default' => 0],       // Must user change password?
            'pwd_reset_at'              => ['type' => 'datetime', 'null' => true],      // Password was last reset at
            'validated'                 => ['type' => 'boolean', 'default' => 0],       // User has been validated
            'reset_hash'                => ['type' => 'varchar', 'constraint' => 255],  // Hash for password reset
            'reset_hash_valid_until'    => ['type' => 'datetime', 'null' => true],      // Hash for password reset is valid until
            'validate_hash'             => ['type' => 'varchar', 'constraint' => 255]   // Hash for user validation
        ]);
        $this->forge->addKey('id', true);
        $this->forge->addUniqueKey('email');
        $this->forge->createTable('users', true);

        /*
         * Log Login Attempts
         */
        $this->forge->addField([
            'id'            => ['type' => 'int', 'constraint' => 11, 'unsigned' => true, 'auto_increment' => true],
            'ip'            => ['type' => 'varchar', 'constraint' => 46, 'null' => true],
            'email'         => ['type' => 'varchar', 'constraint' => 255, 'null' => true],
            'user_id'       => ['type' => 'int', 'constraint' => 11, 'unsigned' => true, 'null' => true], // Only for successful logins
            'date'          => ['type' => 'datetime'],
            'success'       => ['type' => 'tinyint', 'constraint' => 1],
            'user_agent'    => ['type' => 'varchar', 'constraint' => 255],
            'reason'        => ['type' => 'varchar', 'constraint' => 20]
        ]);
        $this->forge->addKey('id', true);
        $this->forge->createTable('auth_login_attempts', true);

        /*
         * Login sessions
         * @see https://paragonie.com/blog/2015/04/secure-authentication-php-with-long-term-persistence
         */
        $this->forge->addField([
            'id'        => ['type' => 'int', 'constraint' => 11, 'unsigned' => true, 'auto_increment' => true],
            'selector'  => ['type' => 'varchar', 'constraint' => 255],
            'validator' => ['type' => 'varchar', 'constraint' => 255],
            'user_id'   => ['type' => 'int', 'constraint' => 11, 'unsigned' => true],
            'expires'   => ['type' => 'datetime'],
            'ip'        => ['type' => 'varchar', 'constraint' => 46]
        ]);
        $this->forge->addKey('id', true);
        $this->forge->addKey('selector');
        $this->forge->addForeignKey('user_id', 'users', 'id', false, 'CASCADE');
        $this->forge->createTable('auth_login_sessions', true);

        /*
         * Auth Roles Table
         */
        $fields = [
            'id'          => ['type' => 'int', 'constraint' => 11, 'unsigned' => true, 'auto_increment' => true],
            'name'        => ['type' => 'varchar', 'constraint' => 255]
        ];
        $this->forge->addField($fields);
        $this->forge->addKey('id', true);
        $this->forge->createTable('auth_roles', true);

        // Add default role
        $data = [
            'name'  => 'Default'
        ];
        $this->db->table('auth_roles')->insert($data);

        /*
         * Auth Permissions Table
         */
        $fields = [
            'id'          => ['type' => 'int', 'constraint' => 11, 'unsigned' => true, 'auto_increment' => true],
            'name'        => ['type' => 'varchar', 'constraint' => 255]
        ];
        $this->forge->addField($fields);
        $this->forge->addKey('id', true);
        $this->forge->createTable('auth_permissions', true);

        /*
         * Roles/Permissions Table
         */
        $fields = [
            'role_id'      => ['type' => 'int', 'constraint' => 11, 'unsigned' => true, 'default' => 0],
            'permission_id' => ['type' => 'int', 'constraint' => 11, 'unsigned' => true, 'default' => 0],
        ];
        $this->forge->addField($fields);
        $this->forge->addKey(['role_id', 'permission_id']);
        $this->forge->addForeignKey('role_id', 'auth_roles', 'id', false, 'CASCADE');
        $this->forge->addForeignKey('permission_id', 'auth_permissions', 'id', false, 'CASCADE');
        $this->forge->createTable('auth_roles_permissions', true);
    }

    //--------------------------------------------------------------------

    public function down()
    {

        $this->forge->dropTable('users', true);
        $this->forge->dropTable('auth_login_attempts', true);
        $this->forge->dropTable('auth_login_sessions', true);
        $this->forge->dropTable('auth_roles', true);
        $this->forge->dropTable('auth_permissions', true);
        $this->forge->dropTable('auth_roles_permissions', true);
    }
}