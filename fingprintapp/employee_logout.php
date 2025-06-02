<?php
session_start();

// Set security headers
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:;");

// Only clear employee-related session variables
unset($_SESSION['employee_id']);
unset($_SESSION['employee_name']);
unset($_SESSION['last_activity']);

// Update session status in database if employee is logged in
if (isset($_SESSION['employee_id'])) {
    require 'db.php';
    $stmt = $conn->prepare("UPDATE sessions SET is_active = 0 WHERE employee_id = ?");
    $stmt->bind_param("i", $_SESSION['employee_id']);
    $stmt->execute();
}

// Redirect to employee login page
header("Location: login.php");
exit;
?> 