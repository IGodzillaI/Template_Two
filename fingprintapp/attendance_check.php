<?php
// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once 'db.php';
require_once 'auth_check.php';

// Ensure database connection is active
$conn = ensureConnection($conn);
if (!$conn) {
    session_unset();
    session_destroy();
    header("Location: login.php?error=db_connection");
    exit;
}

// Check if this is a regular employee (not admin)
$employee = check_employee($conn);

// Continue with attendance page load
$employee_id = $_SESSION['employee_id']; 