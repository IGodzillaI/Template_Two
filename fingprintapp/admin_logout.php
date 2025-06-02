<?php
session_name('admin_session');
session_start();
require 'db.php';

// Set security headers
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:;");

if (isset($_SESSION['admin_cookie'])) {
    // Remove session from database
    $stmt = $conn->prepare("DELETE FROM admin_sessions WHERE session_id = ?");
    $stmt->bind_param("s", $_SESSION['admin_cookie']);
    $stmt->execute();
}

// Clear admin session
session_unset();
session_destroy();

// Clear cookies
if (isset($_COOKIE['admin_cookie'])) {
    setcookie('admin_cookie', '', time() - 600, '/', '', true, true);
}
if (isset($_COOKIE[session_name()])) {
    setcookie(session_name(), '', time() - 600, '/', '', true, true);
}

// Redirect to login page
header("Location: admin_login.php");
exit;
?>