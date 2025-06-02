<?php
/**
 * Authentication and Authorization Helper
 * This file provides functions to check user authentication and authorization
 */

// Check if user is logged in, otherwise redirect to login page
function check_login() {
    if (!isset($_SESSION['employee_id']) || !isset($_SESSION['session_id'])) {
        $_SESSION['error_message'] = "يرجى تسجيل الدخول أولاً";
        header("Location: login.php");
        exit;
    }
    
    // Return employee_id for convenience
    return $_SESSION['employee_id'];
}

// Check if user is an admin, otherwise redirect to attendance page
function check_admin($conn) {
    $employee_id = check_login(); // Also checks if logged in
    
    $stmt = $conn->prepare("SELECT role FROM employees WHERE id = ?");
    $stmt->bind_param("i", $employee_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $employee = $result->fetch_assoc();
    
    if (!$employee || $employee['role'] !== 'admin') {
        $_SESSION['error_message'] = "أنت لا تملك صلاحية الوصول لهذه الصفحة";
        header("Location: attendance.php");
        exit;
    }
    
    // Return employee data for convenience
    return $employee;
}

// Check if user is a regular employee (non-admin), redirect admins to admin page
function check_employee($conn) {
    $employee_id = check_login(); // Also checks if logged in
    
    $stmt = $conn->prepare("SELECT role FROM employees WHERE id = ?");
    $stmt->bind_param("i", $employee_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $employee = $result->fetch_assoc();
    
    if ($employee && $employee['role'] === 'admin') {
        $_SESSION['error_message'] = "صفحة الموظفين غير متاحة للمسؤول، يرجى استخدام لوحة تحكم المسؤول";
        header("Location: admin.php?view=dashboard");
        exit;
    }
    
    // Return employee data for convenience
    return $employee;
} 