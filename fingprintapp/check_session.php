<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
require_once 'db.php';

// Set security headers
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:;");

$timeout = 600; // 10 minutes

// Clean up expired sessions
$stmt = $conn->prepare("DELETE FROM admin_sessions WHERE TIMESTAMPDIFF(SECOND, last_activity, NOW()) > ?");
$stmt->bind_param("i", $timeout);
$stmt->execute();

// Verify admin session
if (!isset($_SESSION['is_admin']) || !isset($_SESSION['admin_cookie'])) {
    clearAdminSession();
    header("Location: admin_login.php");
    exit;
}

$admin_cookie = $_SESSION['admin_cookie'];
$stmt = $conn->prepare("SELECT 1 FROM admin_sessions WHERE session_id = ? AND TIMESTAMPDIFF(SECOND, last_activity, NOW()) <= ?");
$stmt->bind_param("si", $admin_cookie, $timeout);
$stmt->execute();

if ($stmt->get_result()->num_rows === 0) {
    clearAdminSession();
    header("Location: admin_login.php");
    exit;
}

// Update last activity
$stmt = $conn->prepare("UPDATE admin_sessions SET last_activity = NOW() WHERE session_id = ?");
$stmt->bind_param("s", $admin_cookie);
$stmt->execute();

// Helper function to clear admin session
function clearAdminSession() {
    // Clear session data
    unset($_SESSION['is_admin']);
    unset($_SESSION['admin_cookie']);
    
    // Clear cookies
    if (isset($_COOKIE['admin_cookie'])) {
        setcookie('admin_cookie', '', time() - 3600, '/', '', true, true);
    }
    if (isset($_COOKIE[session_name()])) {
        setcookie(session_name(), '', time() - 3600, '/', '', true, true);
    }
    
    // Destroy session
    session_destroy();
}

// Function to check admin session status
function checkAdminSession($conn) {
    if (!isset($_SESSION['is_admin']) || !isset($_SESSION['admin_cookie'])) {
        return false;
    }

    $timeout = 600;
    $admin_cookie = $_SESSION['admin_cookie'];
    
    $stmt = $conn->prepare("SELECT 1 FROM admin_sessions WHERE session_id = ? AND TIMESTAMPDIFF(SECOND, last_activity, NOW()) <= ?");
    $stmt->bind_param("si", $admin_cookie, $timeout);
    $stmt->execute();
    
    if ($stmt->get_result()->num_rows === 0) {
        return false;
    }

    // Update last activity
    $stmt = $conn->prepare("UPDATE admin_sessions SET last_activity = NOW() WHERE session_id = ?");
    $stmt->bind_param("s", $admin_cookie);
    $stmt->execute();

    return true;
}

// Function to check user session status
function checkUserSession($conn) {
    if (!isset($_SESSION['employee_id']) || !isset($_SESSION['session_id'])) {
        return false;
    }

    $timeout = 1800; // 30 minutes
    $employee_id = $_SESSION['employee_id'];
    $session_id = $_SESSION['session_id'];
    
    $stmt = $conn->prepare("SELECT 1 FROM session_id WHERE user_id = ? AND session_id = ? AND TIMESTAMPDIFF(SECOND, last_activity, NOW()) <= ?");
    $stmt->bind_param("isi", $employee_id, $session_id, $timeout);
    $stmt->execute();
    
    if ($stmt->get_result()->num_rows === 0) {
        return false;
    }

    // Update last activity
    $stmt = $conn->prepare("UPDATE session_id SET last_activity = NOW() WHERE user_id = ? AND session_id = ?");
    $stmt->bind_param("is", $employee_id, $session_id);
    $stmt->execute();

    return true;
}
?> 