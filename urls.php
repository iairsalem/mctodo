<?php

function change_http_method(){
    if($_SERVER["REQUEST_METHOD"] == "POST"){
        if(isset($_POST['_method'])){
            $_SERVER["REQUEST_METHOD"] = strtoupper($_POST['_method']);
        }
    }
}
change_http_method();

require 'vendor/autoload.php';
$router = new AltoRouter();

include('views.php');

$router->addRoutes(array(
    array('GET','/static/.[a:file]?', 'serve_file'),
    array('GET','/', 'index'),
    array('GET','/tasks', 'list_tasks'),
    array('GET','/login', 'get_login'),
    array('POST','/login', 'post_login'),
    array('GET','/logout', 'logout'),
    array('GET','/signup', 'get_signup'),
    array('POST','/signup', 'post_signup'),
    array('POST','/task/create/', 'create_task'),
    array('POST','/login', 'authenticate_login'),
    array('PATCH','/task/complete/[i:id]/[a:complete]?/?', 'complete_task'),
));

function serve_file($file){
    echo 'kipe';
    include('static/'.$file);
}

$match = $router->match();

if( is_array($match) && is_callable( $match['target'] ) ) {
    call_user_func_array( $match['target'], $match['params'] );
} else {
    // no route was matched
    header( $_SERVER["SERVER_PROTOCOL"] . ' 404 Not Found');
    echo isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI']: '/';
    echo "\n404";
}