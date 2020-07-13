<?php
//require('header.php');
//require('navbar.php');
global $auth;

$auth->require_logged_in();

$tasks = list_tasks(false);

function checkbox($name, $checked=''){
    return "<input type='checkbox' id='{$name}' $checked>";
}

function img_button($src, $id, $extra = ''){
    return "<img src='static/{$src}' id='{id}' {$extra}>";
}

?>

<div>
    <form method="post" action="/task/create/">
        <input type="text" placeholder="Enter New Task Here" name="task" />
        <input type="submit" value="Create">
        <input type="text" name="_token" value="<?=$_SESSION['_token']?>" style="display:none"/>
    </form>
</div>

<h1>Your Tasks</h1>
<ul>
    <?php
    foreach($tasks['pending']  as $task){
        echo '<li class="task-pending">'.checkbox('task_'.$task['task_id']).$task['name'] . ' '.img_button('edit.svg', 'edit_'. $task['task_id']) . img_button('del.svg', 'del_'. $task['task_id']).'</li>';
    }
    if(empty($tasks['pending'])){
        echo "<strong>No pending Tasks!</strong>";
    }
    ?>
</ul>
<p>Completed:</p>
<ul>
    <?php
        foreach($tasks['completed'] as $task){
            echo '<li class="task-completed">'. checkbox('task_'.$task['task_id'], 'checked').$task['name'].'</li>';
        }
    ?>
</ul>
<template id="pending_task">
    <li class="task-pending">{{checkbox}}{{task_name}}{{edit_button}}{{delete_button}}</li>
</template>
<template id="complete_task">
    <li class="task-completed">{{checkbox}}{{task_name}}{{edit_button}}{{delete_button}}</li>
</template>
<template id="checkbox_template">
    <input type="checkbox" id="{{name}}" {{extra}}>
</template>
<template id="img_template">
    <img src="{{src}}" id="{{id}}" {{extra}}>
</template>
<?php
/*
if ($_SERVER["REQUEST_METHOD"] == "POST"){
    if($_POST['_token'] !=$_SESSION['_token']){
        header("HTTP/1.1 418 I'm a teapot");
        die();
    } else {
        // create new task
        $sql = 'INSERT INTO tasks (name) VALUES (?)';
        $stmt = $conn->prepare($sql)->execute($_POST['task']);
        if($stmt){
            $message = "New Task Created!";
        }
    }
}
*/
/*
$conn = $auth->get_conn();
$sql = 'SELECT * FROM tasks WHERE user_id = :user_id ORDER BY created, completed DESC';
$query = $conn->prepare($sql);
$query->bindValue(':user_id', $_SESSION['user_id']);
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
*/