<?php
if(session_status() == PHP_SESSION_NONE) session_start();
if (empty($_SESSION['_token'])) {
     //CREDITS : https://stackoverflow.com/questions/6287903/how-to-properly-add-csrf-token-using-php
    $_SESSION['_token'] = bin2hex(random_bytes(32));
}

function assert_csrf(){
    if (in_array($_SERVER["REQUEST_METHOD"], ['POST', 'PUT', 'PATCH'])){
         if($_POST['_token'] !=$_SESSION['_token']) {
             header("HTTP/1.1 418 I'm a teapot");
             exit();
         }
    }
}

assert_csrf();
