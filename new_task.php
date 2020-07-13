<?php
$auth->requireLoggedIn();
session_start();
if (empty($_SESSION['token'])) {
    // FOR PHP 7, CREDITS : https://stackoverflow.com/questions/6287903/how-to-properly-add-csrf-token-using-php
    // $_SESSION['token'] = bin2hex(random_bytes(32));
}


$title = 'New Task';
require('header.php');
require('navbar.php');
?>
<form method="post">
    <input type="text" placeholder="Enter New Task Here" />
    <input type="submit" value="New Task">
    <input type="text" name="token" value="<?=$_SESSION['_token']?>" style="display:none"/>
</form>

