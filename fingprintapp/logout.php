<?php
session_start();
require 'db.php';

if (isset($_SESSION['employee_id'])) {
    // Delete the session from session_id table
    $stmt = $conn->prepare("DELETE FROM session_id WHERE user_id = ?");
    $stmt->bind_param("i", $_SESSION['employee_id']);
    $stmt->execute();
}

// Clear all session variables
session_unset();

// Destroy the session
session_destroy();

// Redirect to login page
header("Location: login.php");
exit;
?>