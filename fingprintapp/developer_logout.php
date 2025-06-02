<?php
session_start();
require_once 'developer_db.php';

if (isset($_SESSION['developer_id']) && isset($_SESSION['developer_session'])) {
    // Log activity
    $stmt = $dev_conn->prepare("INSERT INTO developer_activity_log (developer_id, action, ip_address) VALUES (?, 'logout', ?)");
    $stmt->bind_param("is", $_SESSION['developer_id'], $_SERVER['REMOTE_ADDR']);
    $stmt->execute();

    // Remove session from database
    $stmt = $dev_conn->prepare("DELETE FROM developer_sessions WHERE session_id = ?");
    $stmt->bind_param("s", $_SESSION['developer_session']);
    $stmt->execute();
}

// Clear session
session_unset();
session_destroy();

// Redirect to login page
header('Location: developer_login.php');
exit(); 