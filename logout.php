<?php
// session_unset();
require('auth.lib.php');
$auth->doLogout();
$auth->feedback = 'Logged out';
//header("location:javascript://history.go(-1)");
header('Location: /');
//echo '<a href="index.php">Home</a>';