<?php

require 'vendor/autoload.php';
use SimpleAuth\SimpleAuth;

$auth = new SimpleAuth();
$conn = $auth->get_conn();

function index(){
    global $auth;
    include('templates/header.php');
    include('templates/navbar.php');
    if ($auth->is_logged_in()){
        include('templates/task_list.php');
    } else {
        include('templates/guest.php');
    }
    include ('templates/footer.php');
}
function check_login(){
    global $auth;
    if(!$auth->is_logged_in()){
        header('HTTP/1.0 403 Forbidden');
        exit;
    }
    return $auth->user_id();
}

function get_login(){
    include('templates/header.php');
    include('templates/navbar.php');
    include('templates/login.php');
    include('templates/footer.php');
}

function post_login(){
    global $auth;
    if($auth->is_logged_in()){
        header("Location: /");
    }else{
        flash("Bad Login Credentials");
        include('templates/header.php');
        include('templates/navbar.php');
        include('templates/login.php');
        include('templates/footer.php');
    }
}

function logout(){
    global $auth;
    $auth->logout();
    $auth->feedback = 'Logged out';
    header("Location: /");
}
function get_signup(){
    global $auth;
    include('templates/header.php');
    include('templates/navbar.php');
    $auth->show_signup_form();
    include('templates/footer.php');
}

function post_signup(){
    global $auth;
    if($auth->create_new_user()) {
        include('templates/signup_confirmation.php');
    } else {
        include('templates/header.php');
        include('templates/navbar.php');
        $auth->show_signup_form();
        include('templates/footer.php');
    }
}

function create_task($echo = false){
    global $conn;
    $user_id = check_login();
    // create new task
    $sql = 'INSERT INTO tasks (user_id, name) VALUES (?,?)';
    $ret = [];
    if(execute_sql($sql, array($user_id, $_POST['task']))){
        $ret['response'] = true;
    } else{
        $ret['response'] = false;
    }
    if($echo){
        echo json_encode($ret);
    } else {
        flash('Task created.');
        header("Location: /");
        return $ret;
    }
}

function list_tasks($echo = true){
    global $conn;
    $user_id = check_login();
    $sql = 'SELECT * FROM tasks WHERE user_id = :user_id ORDER BY created, completed DESC';
    $query = $conn->prepare($sql);
    $query->bindValue(':user_id', $user_id);
    $query->execute();
    $pending = [];
    $completed = [];
    while($row = $query->fetch(PDO::FETCH_ASSOC)){
        if($row['status'] == 'completed'){
            $completed[] = $row;
        } else {
            $pending[] = $row;
        }
    }
    if($echo){
        echo json_encode(array('pending' => $pending, 'completed' => $completed));
    } else {
        return ['pending'=>$pending, 'completed'=>$completed];
    }
}

function record_exists($sql, $values){
    global $conn;
    $query = $conn->prepare($sql);
    $query->execute($values);
    if($query->fetch()){
        return true;
    }
    return false;
}

function execute_sql ($sql, $values){
    global $conn;
    $query = $conn->prepare($sql);
    $query->execute($values);
    if($query->rowCount() > 0){
        return true;
    }
    return false;
}

function complete_task($id, $complete = 'complete', $echo = true){
    check_login();
    $sql = 'SELECT task_id FROM tasks WHERE user_id = ? and task_id = ? ';
    $params = [];
    $ret = false;
    if(record_exists($sql, array($_SESSION['user_id'], $id))) {
        if($complete){
            $sql = 'UPDATE tasks SET status = `completed`, completed = ?';
            $params[0] = "=datetime('now','localtime')";
        } else {
            $sql = 'UPDATE tasks SET status = `pending`, completed = NULL';
        }
        if(execute_sql($sql, $params)){
            $ret = array('response' => true);
        }
    }
    if(!$ret){
        $ret = array('response' => false);
    }
    if($echo){
        echo json_encode($ret);
    }else{
        return $ret;
    }
}

function flash($message){
    if(!isset($_SESSION["message"])){
        $_SESSION["message"]= array();
    }
    $_SESSION["message"][]=$message;
}