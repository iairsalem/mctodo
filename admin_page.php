<?php

require_once('navbar.php');
if(!$auth->requireAdmin()){
    exit(1);
}

echo "You are admin";