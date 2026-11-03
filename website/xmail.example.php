<?php
// Copy to ignored xmail.local.php, outside public_html. Never commit passwords.
return [
    'username'=>'admin',
    'password_hash'=>'', // password_hash($loginPassword, PASSWORD_DEFAULT)
    'salt'=>'', // random 32 bytes encoded as hex
    'accounts'=>[
        ['id'=>'example','email'=>'example@vampir.top','password'=>''],
    ],
];
