<?php
session_name('admin_session'); // Match the admin session name
session_start();
require 'db.php';

// Verify admin session
if (!isset($_SESSION['is_admin']) || !isset($_SESSION['admin_cookie']) || !isset($_SESSION['admin_id'])) {
    header("Location: admin_login.php");
    exit;
}

// Check if data was submitted
if (!isset($_POST['employeeOrder']) || empty($_POST['employeeOrder'])) {
    $_SESSION['error_message'] = "No employee order data received.";
    header("Location: admin.php");
    exit;
}

try {
    // Decode the JSON data
    $employeeOrder = json_decode($_POST['employeeOrder'], true);
    
    if (!$employeeOrder || !is_array($employeeOrder)) {
        throw new Exception("Invalid employee order data format.");
    }
    
    // Begin transaction
    $conn->begin_transaction();
    
    // Create new sort_order column if it doesn't exist
    $checkColumnSql = "SHOW COLUMNS FROM employees LIKE 'sort_order'";
    $checkColumnResult = $conn->query($checkColumnSql);
    
    if ($checkColumnResult->num_rows === 0) {
        $conn->query("ALTER TABLE employees ADD COLUMN sort_order INT DEFAULT 0");
    }
    
    // First reset all employees sort_order to a high number to avoid unique constraint issues
    $conn->query("UPDATE employees SET sort_order = 10000 + id");
    
    // Update each employee's sort_order
    $updateStmt = $conn->prepare("UPDATE employees SET sort_order = ? WHERE id = ?");
    
    // Track current position for sequential numbering
    $currentPosition = 1;
    
    foreach ($employeeOrder as $item) {
        $id = intval($item['id']);
        // Use sequential position starting from 1
        $position = $currentPosition++;
        
        $updateStmt->bind_param("ii", $position, $id);
        $updateStmt->execute();
    }
    
    // Commit transaction
    $conn->commit();
    
    // Add log of the reordering action
    $admin_id = $_SESSION['admin_id'];
    $logStmt = $conn->prepare("
        INSERT INTO admin_alerts (employee_id, message, device_info, is_read) 
        VALUES (?, 'Admin reordered employees list', 'Admin action from dashboard', 0)
    ");
    $logStmt->bind_param("i", $admin_id);
    $logStmt->execute();
    
    $_SESSION['success_message'] = "Employee order updated successfully!";
} catch (Exception $e) {
    // Roll back in case of error
    if ($conn && $conn->ping()) {
        $conn->rollback();
    }
    $_SESSION['error_message'] = "Error updating employee order: " . $e->getMessage();
}

// Redirect back to admin page
header("Location: admin.php");
exit;
?> 