<?php
// Secure developer database connection
$dev_db_host = 'localhost';
$dev_db_user = 'root';
$dev_db_pass = '';
$dev_db_name = 'fingprintapp';

$dev_conn = new mysqli($dev_db_host, $dev_db_user, $dev_db_pass, $dev_db_name);
if ($dev_conn->connect_error) {
    die('Developer DB Connection failed: ' . $dev_conn->connect_error);
}
$dev_conn->set_charset('utf8mb4');

// Ensure developer_alerts table exists
$dev_conn->query("CREATE TABLE IF NOT EXISTS developer_alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    message VARCHAR(255) NOT NULL,
    created_at DATETIME NOT NULL
)"); 