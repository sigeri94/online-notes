<?php
//https://packetstormsecurity.com/files/50320/ECHO_ADV_47_2006.html
require '/var/www/html/wp-config.php';
require '/var/www/html/wp-includes/pluggable.php';

$hf_user = wp_get_current_user();
$user = $hf_user->user_login;

if (isset($_GET["msg"])) {
        $mess=$_GET["msg"];
        echo "$mess"." "."$user"." !!";
} else {
        echo "Halaman ini vuln terhadap xss dan memiliki cookie wordpress.<br/>";
        echo "Berikan link dengan payload XSS pada admin wordpress server ini yg sedang dalam kondisi login untuk melakukan exploitasi.<br/>";
        echo "exploit link [ <a href='http://192.168.88.108/tes.php?msg=welcome'>ini</a> ]";
}

?>

