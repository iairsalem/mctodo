<ul>
<?php
global $auth;
$user = $auth->is_logged_in();
$admin = $auth->is_admin();

if($admin){
    echo '<li><a href="admin_page.php">Admin Page</a></li>';
}

if($user || $admin){
    echo '<li><a href="/">Home</a></li>';
}else{
    echo '<li><a href="/login">Login</a></li>';
    echo '<li><a href="/signup">Sign Up</a></li>';
}
if($user){
    $user_name = $auth->user_name();
    echo "<li><a href='/logout'>Log Out [{$user_name}]</a></li>";
}
?>
</ul>
<?php
if (isset($_SESSION['message'])){
    if(!is_array($_SESSION['message'])){
        $_SESSION['message'] = array($_SESSION['message']);
    }
    if (!empty($auth->feedback)){
        array_unshift($_SESSION['message'], $auth->feedback);
    }
    foreach ($_SESSION['message'] as $message){
        echo "<div class='message'>{$message}</div>";
    }
    unset($_SESSION['message']);
}