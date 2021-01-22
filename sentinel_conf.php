<?php

$sentinel_logfile = '/var/log/auth.log';
$sentinel_deny    = '/etc/hosts.deny';
$sentinel_maxcount = 3;
$sentinel_time    = 36000; // 10 uur

// array with hostmask
$sentinel_ignore = array(
    '192.168.23',
    '10.0.'
);
