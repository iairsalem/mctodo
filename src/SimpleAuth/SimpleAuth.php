<?php namespace SimpleAuth;

use \PDO;

if(session_status() == PHP_SESSION_NONE) session_start();

if (empty($_SESSION['_token'])) {
    //CREDITS : https://stackoverflow.com/questions/6287903/how-to-properly-add-csrf-token-using-php
    $_SESSION['_token'] = bin2hex(random_bytes(32));
}

function assert_csrf_ok(){
    if (in_array($_SERVER["REQUEST_METHOD"], ['POST', 'PUT', 'PATCH'])){
        if($_POST['_token'] !=$_SESSION['_token']) {
            header("HTTP/1.1 418 I'm a teapot");
            exit();
        }
    }
}

assert_csrf_ok();

/**
 * Class SimpleAuth by #iairsalem
 * Inspired by:
 *
 * Class OneFileLoginApplication
 *
 * An entire php application with user registration, login and logout in one file.
 *
 * @author Panique
 * @link https://github.com/panique/php-login-one-file/
 * @license http://opensource.org/licenses/MIT MIT License
 */

class SimpleAuth{

    private $config_file = 'config.ini';

    private $vars = [];

    private $user = [];

    public function user_name(){
        if(isset($this->user['user_name'])){
            return $this->user['user_name'];
        } else{
            return false;
        }
    }

    public function user_id(){
        if(isset($this->user['user_id'])){
            return $this->user['user_id'];
        } else{
            return false;
        }
    }

    public function user_email(){
        if(isset($this->user['user_email'])){
            return $this->user['user_email'];
        } else{
            return false;
        }
    }

    public function __construct(){
        if($conf = getenv('MYAUTHVARS')){
            $config = json_decode($conf);
        }else{
            $config = parse_ini_file($this->config_file);
            putenv('MYAUTHVARS=' . json_encode($config));
        }
        $this->vars['db_type'] = $config['db_type'];
        $this->vars['db_sqlite_path'] = $config['db_sqlite_path'];
        $this->connect();
        if(!$this->try_log_in_post()){
            if(!$this->try_log_in_session()){
                $this->user_is_logged_in = false;
                $this->user['is_admin'] = false;
            }
        }
    }

    public function try_log_in_post(){
        if(isset($_POST['login'])){
            return $this->validate_login();
        }
        return false;
    }

    public function try_log_in_session(){
        if(isset($_SESSION['user_is_logged_in'])){
            $this->user['user_name'] = $_SESSION['user']['user_name'];
            $this->user['user_email'] = $_SESSION['user']['user_email'];
            $this->user_is_logged_in = true;
            $this->user['user_id'] = $_SESSION['user']['user_id'];
            $this->user['is_admin'] = $_SESSION['user']['is_admin'];
            return true;
        }
        return false;
    }

    /*
     * Create Table
     */
    public function up(){
        try{
            $this->connect();
            $conn = $this->get_conn();
            $sql = 'CREATE TABLE "users" (
                "user_id"	INTEGER PRIMARY KEY AUTOINCREMENT,
                "user_name"	varchar(64),
                "user_password_hash"	varchar(255),
                "user_email"	varchar(64),
                "is_admin"	INTEGER NOT NULL DEFAULT 0
            );';

            $conn->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );//Error Handling
            $conn->exec($sql);
        } catch(PDOException $e) {
            //echo $e->getMessage();//Remove or change message in production code
        }
    }

    public function is_logged_in(){
        return $this->user_is_logged_in;
    }

    public function is_admin(){
        return $this->user['is_admin'];
    }


    public function connect(){
        try {
            $this->vars['db_connection'] = new PDO($this->vars['db_type'] . ':' . $this->vars['db_sqlite_path']);
            return true;
        } catch (PDOException $e) {
            $this->feedback = "PDO database connection problem: " . $e->getMessage();
        } catch (Exception $e) {
            $this->feedback = "General problem: " . $e->getMessage();
        }
        return false;
    }

    public function get_conn(){
        return $this->vars['db_connection'];
    }

    public function show_login_form($action='/login', $class='myauth'){
        ?>
        <form method="post" action="<?=$action ?>" class="<?=$class ?>">
        <label for="login_input_username">Username (or email)</label>
        <input id="login_input_username" type="text" name="user_name" required />
        <label for="login_input_password">Password</label>
        <input id="login_input_password" type="password" name="user_password" required />
        <input type='hidden' name='_token' style='display:none;' value='<?=$_SESSION["_token"]?>' />
        <input type="submit" name="login" value="Log in" />
        </form>
<?php
    }

    public function show_signup_form($action = '/signup', $class='myauth'){
    ?>
        <form method="post" action="<?=$action?>" class="<?=$class?>">
            <label for="login_input_username">Username (only letters and numbers, 2 to 64 characters)</label>
            <input id="login_input_username" type="text" pattern="[a-zA-Z0-9]{2,64}" name="user_name" required />
            <label for="login_input_email">User\'s email</label>
            <input id="login_input_email" type="email" name="user_email" required />
            <label for="login_input_password_new">Password (min. 6 characters)</label>
            <input id="login_input_password_new" class="login_input" type="password" name="user_password_new" pattern=".{6,}" required autocomplete="off" />
            <label for="login_input_password_repeat">Repeat password</label>
            <input id="login_input_password_repeat" class="login_input" type="password" name="user_password_repeat" pattern=".{6,}" required autocomplete="off" />
            <input type='hidden' name='_token' style='display:none;' value='<?=$_SESSION["_token"]?>' />
            <input type="submit" name="signup" value="Sign Up" />
        </form>
    <?php
    }

    public function validate_login(){
        $sql = 'SELECT user_id, user_name, user_email, user_password_hash, is_admin
                FROM users
                WHERE user_name = :user_name OR user_email = :user_name
                LIMIT 1';
        $query = $this->vars['db_connection']->prepare($sql);
        $query->bindValue(':user_name', $_POST['user_name']);
        $query->execute();

        $result_row = $query->fetchObject();
        if ($result_row) {
            if (password_verify($_POST['user_password'], $result_row->user_password_hash)) {
                // write user data into PHP SESSION [a file on your server]
                $this->user_is_logged_in = true;
                $this->user['user_name'] = $result_row->user_name;
                $this->user['user_email'] = $result_row->user_email;
                $this->user['user_id'] = $result_row->user_id;

                if($result_row->is_admin == 1){
                    $this->user['is_admin'] = true;
                } else {
                    $this->user['is_admin'] = false;
                }
                /*
                $_SESSION['user_name'] = $result_row->user_name;
                $_SESSION['user_email'] = $result_row->user_email;
                $_SESSION['user_id'] = $result_row->user_id;
                */

                $_SESSION['user'] = $this->user;
                $_SESSION['user_is_logged_in'] = true;
                return true;
            } else {
                $this->user_is_logged_in = false;
                $this->feedback = "Wrong password.";
            }
        } else {
            $this->user_is_logged_in = false;
            $this->feedback = "This user does not exist.";
        }
        // default return
        return false;
    }

    public function validate_registration(){
        // if no registration form submitted: exit the method
        if (!isset($_POST["signup"])) {
            return false;
        }

        // validating the input
        if (!empty($_POST['user_name'])
            && strlen($_POST['user_name']) <= 64
            && strlen($_POST['user_name']) >= 2
            && preg_match('/^[a-z\d]{2,64}$/i', $_POST['user_name'])
            && !empty($_POST['user_email'])
            && strlen($_POST['user_email']) <= 64
            && filter_var($_POST['user_email'], FILTER_VALIDATE_EMAIL)
            && !empty($_POST['user_password_new'])
            && strlen($_POST['user_password_new']) >= 6
            && !empty($_POST['user_password_repeat'])
            && ($_POST['user_password_new'] === $_POST['user_password_repeat'])
        ) {
            // only this case return true, only this case is valid
            return true;
        } elseif (empty($_POST['user_name'])) {
            $this->feedback = "Empty Username";
        } elseif (empty($_POST['user_password_new']) || empty($_POST['user_password_repeat'])) {
            $this->feedback = "Empty Password";
        } elseif ($_POST['user_password_new'] !== $_POST['user_password_repeat']) {
            $this->feedback = "Password and password repeat are not the same";
        } elseif (strlen($_POST['user_password_new']) < 6) {
            $this->feedback = "Password has a minimum length of 6 characters";
        } elseif (strlen($_POST['user_name']) > 64 || strlen($_POST['user_name']) < 2) {
            $this->feedback = "Username cannot be shorter than 2 or longer than 64 characters";
        } elseif (!preg_match('/^[a-z\d]{2,64}$/i', $_POST['user_name'])) {
            $this->feedback = "Username does not fit the name scheme: only a-Z and numbers are allowed, 2 to 64 characters";
        } elseif (empty($_POST['user_email'])) {
            $this->feedback = "Email cannot be empty";
        } elseif (strlen($_POST['user_email']) > 64) {
            $this->feedback = "Email cannot be longer than 64 characters";
        } elseif (!filter_var($_POST['user_email'], FILTER_VALIDATE_EMAIL)) {
            $this->feedback = "Your email address is not in a valid email format";
        } else {
            $this->feedback = "An unknown error occurred.";
        }

        // default return
        return false;
    }

    /**
     * Creates a new user.
     * @return bool Success status of user registration
     */
    public function create_new_user()
    {
        if(!$this->validate_registration()){
            return false;
        }
        // remove html code etc. from username and email
        $user_name = htmlentities($_POST['user_name'], ENT_QUOTES);
        $user_email = htmlentities($_POST['user_email'], ENT_QUOTES);
        $user_password = $_POST['user_password_new'];
        // crypt the user's password with the PHP 5.5's password_hash() function, results in a 60 char hash string.
        // the constant PASSWORD_DEFAULT comes from PHP 5.5 or the password_compatibility_library
        $user_password_hash = password_hash($user_password, PASSWORD_DEFAULT);

        $sql = 'SELECT * FROM users WHERE user_name = :user_name OR user_email = :user_email';
        $query = $this->get_conn()->prepare($sql);
        $query->bindValue(':user_name', $user_name);
        $query->bindValue(':user_email', $user_email);
        $query->execute();

        // As there is no numRows() in SQLite/PDO (!!) we have to do it this way:
        // If you meet the inventor of PDO, punch him. Seriously.
        $result_row = $query->fetchObject();
        if ($result_row) {
            $this->feedback = "Sorry, that username / email is already taken. Please choose another one.";
        } else {
            $sql = 'INSERT INTO users (user_name, user_password_hash, user_email)
                    VALUES(:user_name, :user_password_hash, :user_email)';
            $query = $this->get_conn()->prepare($sql);
            $query->bindValue(':user_name', $user_name);
            $query->bindValue(':user_password_hash', $user_password_hash);
            $query->bindValue(':user_email', $user_email);
            // PDO's execute() gives back TRUE when successful, FALSE when not
            // @link http://stackoverflow.com/q/1661863/1114320
            $registration_success_state = $query->execute();

            if ($registration_success_state) {
                $this->feedback = "Your account has been created successfully. You can now log in.";
                return true;
            } else {
                $this->feedback = "Sorry, your registration failed. Please go back and try again.";
            }
        }
        // default return
        return false;
    }

    public function logout()
    {
        $_SESSION = array();
        session_destroy();
        $this->user['user_is_logged_in'] = false;
        $this->user['is_admin'] = false;
        $this->feedback = "You were just logged out.";
    }

    public function require_logged_in(){
        if($this->is_logged_in()){
            return true;
        } else {
            $this->show_login_form();
            return false;
        }
    }
}