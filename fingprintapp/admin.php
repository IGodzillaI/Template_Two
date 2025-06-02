<?php
session_name('admin_session'); // Give admin session a unique name
session_start();
require 'db.php';
require 'theme_helper.php'; // Include theme helper
require 'license_verifier.php'; // Include license verifier

$timeout = 600; // 10 minutes in seconds

// Set security headers
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:;");

// Verify license
$verifier = new LicenseVerifier('admin');
$license_result = $verifier->verifyLicense();

if (!$license_result['valid']) {
    // Redirect to license activation page
    header("Location: activate_license.php?type=admin");
    exit;
}

// Check if license is suspended
$license_status = $verifier->getLicenseStatus();
$is_suspended = $license_status === 'suspended';

// Handle AJAX request for employee data
if (isset($_GET['get_employees']) && $_GET['get_employees'] === 'true') {
    header('Content-Type: application/json');
    // Query employees, including location fields
    $employees_query = $conn->query("SELECT id, name, email, allowed_latitude, allowed_longitude, allowed_range_meters FROM employees ORDER BY name ASC");
    $employees_data = [];
    if ($employees_query) {
        while ($row = $employees_query->fetch_assoc()) {
            $employees_data[] = $row;
        }
    }
    echo json_encode($employees_data);
    exit;
}

// Helper Functions
function verifyAdminSession($conn, $timeout)
{
    if (!isset($_SESSION['is_admin']) || !isset($_SESSION['admin_cookie'])) {
        header("Location: admin_login.php");
        exit;
    }

    $admin_cookie = $_SESSION['admin_cookie'];
    $stmt = $conn->prepare("SELECT 1 FROM admin_sessions WHERE session_id = ? AND TIMESTAMPDIFF(SECOND, last_activity, NOW()) <= ?");
    $stmt->bind_param("si", $admin_cookie, $timeout);
    $stmt->execute();
    if ($stmt->get_result()->num_rows === 0) {
        session_unset();
        session_destroy();
        header("Location: admin_login.php");
        exit;
    }

    $stmt = $conn->prepare("UPDATE admin_sessions SET last_activity = NOW() WHERE session_id = ?");
    $stmt->bind_param("s", $admin_cookie);
    $stmt->execute();
}

function getEmployeeStatus($attendance)
{
    if (!$attendance) {
        return '<span class="badge bg-secondary">Not Started</span>';
    }

    if ($attendance['check_out']) {
        return '<span class="badge bg-success">Completed</span>';
    } elseif ($attendance['break_end']) {
        return '<span class="badge bg-info">After Break</span>';
    } elseif ($attendance['break_start']) {
        return '<span class="badge bg-warning">On Break</span>';
    } elseif ($attendance['check_in']) {
        return '<span class="badge bg-primary">Working</span>';
    }

    return '<span class="badge bg-secondary">Not Started</span>';
}

function getBreakStatus($attendance, $emp_id, $is_checked_out = false)
{
    global $conn;

    if (!$attendance) {
        return '---';
    }

    $output = '';

    if ($attendance['break_start'] && !$attendance['break_end']) {
        // Get scheduled end time from break_schedule
        $stmt = $conn->prepare("
            SELECT scheduled_end 
            FROM break_schedule 
            WHERE employee_id = ? 
            AND actual_end IS NULL 
            ORDER BY id DESC 
            LIMIT 1
        ");
        $stmt->bind_param("i", $emp_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $schedule = $result->fetch_assoc();

        $break_start = new DateTime($attendance['break_start']);
        $now = new DateTime();
        $scheduled_end = new DateTime($schedule['scheduled_end']);

        // Calculate elapsed and remaining time
        $elapsed = $break_start->diff($now);
        $elapsed_minutes = ($elapsed->h * 60) + $elapsed->i;

        $remaining = $now->diff($scheduled_end);
        $remaining_minutes = ($remaining->h * 60) + $remaining->i;

        $output = '
            <div class="alert alert-warning p-2 mb-2">
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <strong><i class="bi bi-cup-hot me-1"></i> On Break</strong>
                    <span class="badge bg-danger break-timer-element" data-start-time="' . $attendance['break_start'] . '" data-elapsed-seconds="' . ($elapsed_minutes * 60) . '">0m 0s</span>
                </div>
                <div class="d-flex justify-content-between mb-1">
                    <small>Started:</small>
                    <span>' . $break_start->format('h:i:s A') . '</span>
                </div>
                <div class="d-flex justify-content-between mb-1">
                    <small>End Time:</small>
                    <span>' . $scheduled_end->format('h:i:s A') . '</span>
                </div>
                <div class="d-flex justify-content-between mb-2">
                    <small>Remaining:</small>
                    <span>~' . $remaining_minutes . ' minutes</span>
                </div>
                <button type="button" class="btn btn-danger btn-sm w-100" data-bs-toggle="modal" data-bs-target="#endBreakModal' . $emp_id . '">
                    <i class="bi bi-cup"></i> End Break
                </button>
            </div>';
    } elseif ($attendance['check_in'] && !$is_checked_out && (!$attendance['break_start'] || ($attendance['break_start'] && $attendance['break_end']))) {
        // Get last break info if exists
        if ($attendance['break_start'] && $attendance['break_end']) {
            $break_start = new DateTime($attendance['break_start']);
            $break_end = new DateTime($attendance['break_end']);

            // Calculate duration
            $duration = $break_start->diff($break_end);
            $duration_minutes = ($duration->h * 60) + $duration->i;

            $output = '
                <div class="alert alert-info p-2 mb-2">
                    Last Break:<br>
                    Start: ' . $break_start->format('h:i:s A') . '<br>
                    End: ' . $break_end->format('h:i:s A') . '<br>
                    Duration: ' . $duration_minutes . ' minutes
                </div>';
        }

        // Add button to open break modal
        $output .= '
            <button type="button" class="btn btn-warning btn-sm" data-bs-toggle="modal" data-bs-target="#startBreakModal' . $emp_id . '">
                <i class="bi bi-cup-hot"></i> Manage Break
            </button>
        ';
    } else {
        $output = '---';
    }

    return $output;
}

// Verify admin session
if (!isset($_SESSION['is_admin']) || !isset($_SESSION['admin_cookie']) || !isset($_SESSION['admin_id'])) {
    session_unset();
    session_destroy();
    header("Location: admin_login.php");
    exit;
}

// Verify active session in database
$stmt = $conn->prepare("SELECT 1 FROM admin_sessions WHERE session_id = ? AND admin_id = ? AND last_activity > DATE_SUB(NOW(), INTERVAL 5 MINUTE)");
$stmt->bind_param("si", $_SESSION['admin_cookie'], $_SESSION['admin_id']);
$stmt->execute();

if ($stmt->get_result()->num_rows === 0) {
    // Session expired or invalid
    $stmt = $conn->prepare("DELETE FROM admin_sessions WHERE admin_id = ?");
    $stmt->bind_param("i", $_SESSION['admin_id']);
    $stmt->execute();

    session_unset();
    session_destroy();
    header("Location: admin_login.php?error=session_expired");
    exit;
}

// Handle Mark All as Read and Clear All Recent Activity
if (isset($_POST['mark_all_read'])) {
    $conn->query("UPDATE admin_alerts SET is_read = 1");
    $_SESSION['success_message'] = "All alerts marked as read";
    header("Location: admin.php?view=dashboard");
    exit;
}

if (isset($_POST['clear_all_activity'])) {
    $conn->query("DELETE FROM admin_alerts");
    $_SESSION['success_message'] = "All activity cleared successfully";
    header("Location: admin.php?view=dashboard");
    exit;
}

// Update last activity
$stmt = $conn->prepare("UPDATE admin_sessions SET last_activity = NOW() WHERE session_id = ? AND admin_id = ?");
$stmt->bind_param("si", $_SESSION['admin_cookie'], $_SESSION['admin_id']);
$stmt->execute();

// Handle logout
if (isset($_GET['logout'])) {
    $stmt = $conn->prepare("DELETE FROM admin_sessions WHERE admin_id = ?");
    $stmt->bind_param("i", $_SESSION['admin_id']);
    $stmt->execute();

    session_unset();
    session_destroy();
    header("Location: admin_login.php");
    exit;
}

// Ensure database connection
$conn = ensureConnection($conn);
if (!$conn) {
    $_SESSION['error_message'] = "Database connection error. Please try again.";
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Handle Actions
if (isset($_POST['clear_history'])) {
    try {
        $conn->begin_transaction();
        $stmt = $conn->prepare("TRUNCATE TABLE admin_access_attempts");
        if (!$stmt->execute()) {
            throw new Exception("Failed to clear access history");
        }
        $conn->commit();
        $_SESSION['success_message'] = "Access history cleared successfully!";
    } catch (Exception $e) {
        $conn->rollback();
        $_SESSION['error_message'] = "Error clearing access history: " . $e->getMessage();
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

if (isset($_POST['logout_employee']) && isset($_POST['id'])) {
    $emp_id = intval($_POST['id']);
    try {
        $conn->begin_transaction();

        // Delete from session_id table
        $stmt = $conn->prepare("DELETE FROM session_id WHERE user_id = ?");
        $stmt->bind_param("i", $emp_id);
        $stmt->execute();

        // Insert into force_logout table
        $stmt = $conn->prepare("INSERT INTO force_logout (user_id) VALUES (?)");
        $stmt->bind_param("i", $emp_id);
        $stmt->execute();

        // Update attendance
        $stmt = $conn->prepare("UPDATE attendance SET check_out = NOW() WHERE employee_id = ? AND date = CURRENT_DATE AND check_in IS NOT NULL AND check_out IS NULL");
        $stmt->bind_param("i", $emp_id);
        $stmt->execute();

        $conn->commit();
        $_SESSION['success_message'] = "Employee logged out successfully.";
    } catch (Exception $e) {
        $conn->rollback();
        $_SESSION['error_message'] = "Error logging out employee: " . $e->getMessage();
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

if (isset($_GET['delete']) && is_numeric($_GET['delete'])) {
    $delete_id = intval($_GET['delete']);
    try {
        $conn->begin_transaction();

        // Delete related records
        $tables = ['attendance', 'session_id', 'fingerprints', 'employees'];
        foreach ($tables as $table) {
            $stmt = $conn->prepare("DELETE FROM $table WHERE " . ($table === 'employees' ? 'id' : 'id') . " = ?");
            $stmt->bind_param("i", $delete_id);
            $stmt->execute();
        }

        $conn->commit();
        $_SESSION['success_message'] = "Employee Deleted Successfully ✔️";
    } catch (Exception $e) {
        $conn->rollback();
        $_SESSION['error_message'] = "Error deleting employee: " . $e->getMessage();
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Handle break actions
if (isset($_POST['add_break']) && isset($_POST['id'])) {
    $emp_id = intval($_POST['id']);
    $break_minutes = isset($_POST['break_minutes']) ? intval($_POST['break_minutes']) : 15;
    $break_type = isset($_POST['break_type']) ? $_POST['break_type'] : 'lunch';

    // Validate break minutes
    if ($break_minutes < 5) $break_minutes = 5;
    if ($break_minutes > 60) $break_minutes = 60;

    try {
        $conn->begin_transaction();

        // Get current time
        $current_time = new DateTime();
        $break_start = $current_time->format('Y-m-d H:i:s');

        // Calculate break end time
        $current_time->add(new DateInterval("PT{$break_minutes}M"));
        $break_end = $current_time->format('Y-m-d H:i:s');

        // Start break
        $stmt = $conn->prepare("UPDATE attendance SET break_start = ?, break_end = NULL WHERE employee_id = ? AND date = CURRENT_DATE AND check_in IS NOT NULL AND check_out IS NULL
        AND (break_start IS NULL OR (break_start IS NOT NULL AND break_end IS NOT NULL))");
        $stmt->bind_param("si", $break_start, $emp_id);

        if ($stmt->execute() && $stmt->affected_rows > 0) {
            // Insert into break_schedule table
            $stmt = $conn->prepare("
                INSERT INTO break_schedule (employee_id, break_start, scheduled_end, created_at, break_type)
                VALUES (?, ?, ?, NOW(), ?)
            ");
            $stmt->bind_param("isss", $emp_id, $break_start, $break_end, $break_type);
            $stmt->execute();

            // Get employee name
            $emp_stmt = $conn->prepare("SELECT name FROM employees WHERE id = ?");
            $emp_stmt->bind_param("i", $emp_id);
            $emp_stmt->execute();
            $emp_result = $emp_stmt->get_result();
            $emp_name = "Employee";
            if ($emp_row = $emp_result->fetch_assoc()) {
                $emp_name = $emp_row['name'];
            }

            // Add record to admin_alerts table for tracking
            $alert_message = ucfirst($break_type) . " break started for " . $emp_name . " (" . $break_minutes . " minutes)";
            $alert_stmt = $conn->prepare("
                INSERT INTO admin_alerts (employee_id, message, device_info, is_read) 
                VALUES (?, ?, 'Admin action from dashboard', 0)
            ");
            $alert_stmt->bind_param("is", $emp_id, $alert_message);
            $alert_stmt->execute();

            $conn->commit();
            $_SESSION['success_message'] = ucfirst($break_type) . " break started successfully for {$break_minutes} minutes";
        } else {
            throw new Exception("Cannot start break. Employee might be on break or not checked in.");
        }
    } catch (Exception $e) {
        $conn->rollback();
        $_SESSION['error_message'] = "Error starting break: " . $e->getMessage();
    }

    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Handle end break action
if (isset($_POST['end_break']) && isset($_POST['id'])) {
    $emp_id = intval($_POST['id']);

    try {
        $conn->begin_transaction();

        // Get break details first (for alert message)
        $break_stmt = $conn->prepare("
            SELECT bs.break_type, bs.break_start, e.name 
            FROM break_schedule bs
            JOIN employees e ON bs.employee_id = e.id
            WHERE bs.employee_id = ? 
            AND bs.actual_end IS NULL 
            ORDER BY bs.id DESC 
            LIMIT 1
        ");
        $break_stmt->bind_param("i", $emp_id);
        $break_stmt->execute();
        $break_details = $break_stmt->get_result()->fetch_assoc();

        // End break
        $stmt = $conn->prepare("
            UPDATE attendance 
            SET break_end = NOW()
            WHERE employee_id = ? 
            AND date = CURRENT_DATE 
            AND break_start IS NOT NULL 
            AND break_end IS NULL
        ");
        $stmt->bind_param("i", $emp_id);

        if ($stmt->execute() && $stmt->affected_rows > 0) {
            // Get current time
            $end_time_query = $conn->query("SELECT NOW() as end_time");
            $end_time_row = $end_time_query->fetch_assoc();
            $end_time = new DateTime($end_time_row['end_time']);

            // Update break_schedule table
            $update_stmt = $conn->prepare("
                UPDATE break_schedule 
                SET actual_end = NOW()
                WHERE employee_id = ? 
                AND actual_end IS NULL 
                ORDER BY id DESC 
                LIMIT 1
            ");
            $update_stmt->bind_param("i", $emp_id);
            $update_stmt->execute();

            // Calculate break duration if we have the details
            if ($break_details) {
                $break_type = ucfirst($break_details['break_type'] ?? 'break');
                $emp_name = $break_details['name'] ?? 'Employee';
                $break_start = new DateTime($break_details['break_start']);
                $duration_mins = ceil(($end_time->getTimestamp() - $break_start->getTimestamp()) / 60);

                // Add record to admin_alerts table for tracking
                $alert_message = "$break_type break ended for $emp_name (duration: $duration_mins minutes)";
                $alert_stmt = $conn->prepare("
                    INSERT INTO admin_alerts (employee_id, message, device_info, is_read) 
                    VALUES (?, ?, 'Admin action from dashboard', 0)
                ");
                $alert_stmt->bind_param("is", $emp_id, $alert_message);
                $alert_stmt->execute();

                $_SESSION['success_message'] = "$break_type break ended successfully after $duration_mins minutes";
            } else {
                $_SESSION['success_message'] = "Break ended successfully";
            }

            $conn->commit();
        } else {
            throw new Exception("Cannot end break. Employee might not be on break.");
        }
    } catch (Exception $e) {
        $conn->rollback();
        $_SESSION['error_message'] = "Error ending break: " . $e->getMessage();
    }

    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Fetch Data
// Query employees with custom order if sort_order column exists
$checkSortOrder = $conn->query("SHOW COLUMNS FROM employees LIKE 'sort_order'");
if ($checkSortOrder->num_rows > 0) {
    $employees = $conn->query("SELECT * FROM employees ORDER BY sort_order ASC, id ASC");
} else {
    $employees = $conn->query("SELECT * FROM employees ORDER BY id ASC");
}

// Get today's attendance
$today = date('Y-m-d');
$attendance_stmt = $conn->prepare("SELECT * FROM attendance WHERE employee_id = ? AND date = ?");
$attendance_data = [];

if ($employees) {
    while ($emp = $employees->fetch_assoc()) {
        $attendance_stmt->bind_param("is", $emp['id'], $today);
        $attendance_stmt->execute();
        $result = $attendance_stmt->get_result();
        $attendance_data[$emp['id']] = $result->fetch_assoc();
    }
    $employees->data_seek(0);
}

// Get active sessions
$active_sessions = $conn->query("
    SELECT user_id 
    FROM session_id 
    WHERE TIMESTAMPDIFF(SECOND, last_activity, NOW()) <= 1800")->fetch_all(MYSQLI_ASSOC);
$logged_in_employees = array_column($active_sessions, 'user_id');

// Get access attempts
$access_attempts = [];
try {
    $stmt = $conn->prepare("
        SELECT id, username, ip_address, user_agent, device_details, attempt_time
        FROM admin_access_attempts 
        ORDER BY attempt_time DESC 
        LIMIT 50
    ");
    if ($stmt->execute()) {
        $result = $stmt->get_result();
        $access_attempts = $result->fetch_all(MYSQLI_ASSOC);
    }
} catch (Exception $e) {
    error_log("Error fetching access attempts: " . $e->getMessage());
}

// Get messages
$message = $_SESSION['success_message'] ?? '';
$error_message = $_SESSION['error_message'] ?? '';
unset($_SESSION['success_message'], $_SESSION['error_message']);

// Add this to the PHP section at the top of the file where other actions are handled

if (isset($_POST['verify_employee']) && isset($_POST['id'])) {
    $emp_id = intval($_POST['id']);

    try {
        $conn->begin_transaction();

        // Update employee status
        $stmt = $conn->prepare("UPDATE employees SET is_verified = 1 WHERE id = ?");
        $stmt->bind_param("i", $emp_id);
        if (!$stmt->execute()) {
            throw new Exception("Error updating employee status: " . $stmt->error);
        }

        // Mark all OTP records as used
        $stmt = $conn->prepare("UPDATE employee_otp SET is_used = 1 WHERE employee_id = ?");
        $stmt->bind_param("i", $emp_id);
        if (!$stmt->execute()) {
            throw new Exception("Error updating OTP records: " . $stmt->error);
        }

        $conn->commit();
        $_SESSION['success_message'] = "Employee verified successfully!";
    } catch (Exception $e) {
        $conn->rollback();
        $_SESSION['error_message'] = "Error verifying employee: " . $e->getMessage();
    }

    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Count unread alerts
$alertsQuery = $conn->query("SELECT COUNT(*) as count FROM admin_alerts WHERE is_read = 0");
$alertsCount = $alertsQuery->fetch_assoc()['count'];

// Count total employees
$employeesQuery = $conn->query("SELECT COUNT(*) as count FROM employees");
$employeesCount = $employeesQuery->fetch_assoc()['count'];

// Count employees on break
$onBreakQuery = $conn->query(
    "
    SELECT COUNT(*) as count 
    FROM attendance 
    WHERE date = CURDATE() 
    AND break_start IS NOT NULL 
    AND break_end IS NULL"
);
$onBreakCount = $onBreakQuery->fetch_assoc()['count'];

// Count checked in employees
$checkedInQuery = $conn->query(
    "
    SELECT COUNT(*) as count 
    FROM attendance 
    WHERE date = CURDATE() 
    AND check_in IS NOT NULL 
    AND check_out IS NULL"
);
$checkedInCount = $checkedInQuery->fetch_assoc()['count'];

// Get view mode (dashboard or employees list)
$view_mode = $_GET['view'] ?? 'employees';

// Add this to the PHP section where other actions are handled for force checkout and admin break control
if (isset($_POST['force_checkout']) && isset($_POST['id'])) {
    $emp_id = intval($_POST['id']);
    try {
        $conn->begin_transaction();

        // Use server timestamp for forced checkout
        $stmt = $conn->prepare("UPDATE attendance SET check_out = NOW() WHERE employee_id = ? AND date = CURRENT_DATE AND check_in IS NOT NULL AND check_out IS NULL");
        $stmt->bind_param("i", $emp_id);

        // Auto end break if still on break
        $break_stmt = $conn->prepare("
            UPDATE attendance 
            SET break_end = NOW()
            WHERE employee_id = ? 
            AND date = CURRENT_DATE 
            AND break_start IS NOT NULL 
            AND break_end IS NULL
        ");
        $break_stmt->bind_param("i", $emp_id);
        $break_stmt->execute();

        // Update break schedule
        $break_schedule_stmt = $conn->prepare("
            UPDATE break_schedule 
            SET actual_end = NOW()
            WHERE employee_id = ? 
            AND actual_end IS NULL 
            ORDER BY id DESC 
            LIMIT 1
        ");
        $break_schedule_stmt->bind_param("i", $emp_id);
        $break_schedule_stmt->execute();

        if ($stmt->execute()) {
            // Add record to admin_alerts table for tracking
            $alert_stmt = $conn->prepare("
                INSERT INTO admin_alerts (employee_id, message, device_info, is_read) 
                VALUES (?, 'Admin forced early checkout', 'Admin action from dashboard', 0)
            ");
            $alert_stmt->bind_param("i", $emp_id);
            $alert_stmt->execute();

            $conn->commit();
            $_SESSION['success_message'] = "Employee checkout forced successfully";
        } else {
            throw new Exception("Failed to force checkout");
        }
    } catch (Exception $e) {
        $conn->rollback();
        $_SESSION['error_message'] = "Error forcing checkout: " . $e->getMessage();
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Admin add break action
if (isset($_POST['admin_add_break']) && isset($_POST['id'])) {
    $emp_id = intval($_POST['id']);
    try {
        $conn->begin_transaction();

        // Use server time for break start
        $stmt = $conn->prepare("UPDATE attendance SET break_start = NOW() WHERE employee_id = ? AND date = CURRENT_DATE AND check_in IS NOT NULL AND check_out IS NULL");
        $stmt->bind_param("i", $emp_id);

        if ($stmt->execute() && $stmt->affected_rows > 0) {
            // Get the actual break start time from server for consistency
            $break_start_query = $conn->query("SELECT NOW() as break_start_time");
            $break_start_row = $break_start_query->fetch_assoc();

            // Calculate scheduled end time (15 minutes after break start)
            $break_start_time = new DateTime($break_start_row['break_start_time']);
            $break_end_time = clone $break_start_time;
            $break_end_time->modify('+15 minutes');
            $scheduled_end = $break_end_time->format('Y-m-d H:i:s');

            // Insert break schedule
            $stmt = $conn->prepare("INSERT INTO break_schedule (employee_id, break_start, scheduled_end) VALUES (?, NOW(), ?)");
            $stmt->bind_param("is", $emp_id, $scheduled_end);
            $stmt->execute();

            // Add record to admin_alerts table for tracking
            $alert_stmt = $conn->prepare("
                INSERT INTO admin_alerts (employee_id, message, device_info, is_read) 
                VALUES (?, 'Admin started break for employee', 'Admin action from dashboard', 0)
            ");
            $alert_stmt->bind_param("i", $emp_id);
            $alert_stmt->execute();

            $conn->commit();
            $_SESSION['success_message'] = "Break started for employee successfully";
        } else {
            throw new Exception("Cannot start break. Employee might be on break or not checked in.");
        }
    } catch (Exception $e) {
        $conn->rollback();
        $_SESSION['error_message'] = "Error starting break: " . $e->getMessage();
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Admin end break action
if (isset($_POST['admin_end_break']) && isset($_POST['id'])) {
    $emp_id = intval($_POST['id']);
    try {
        $conn->begin_transaction();

        // Use server time for break end
        $stmt = $conn->prepare("UPDATE attendance SET break_end = NOW() WHERE employee_id = ? AND date = CURRENT_DATE AND break_start IS NOT NULL AND break_end IS NULL");
        $stmt->bind_param("i", $emp_id);

        if ($stmt->execute() && $stmt->affected_rows > 0) {
            // Update break schedule
            $stmt = $conn->prepare("
                UPDATE break_schedule 
                SET actual_end = NOW()
                WHERE employee_id = ? 
                AND actual_end IS NULL 
                ORDER BY id DESC 
                LIMIT 1
            ");
            $stmt->bind_param("i", $emp_id);
            $stmt->execute();

            // Add record to admin_alerts table for tracking
            $alert_stmt = $conn->prepare("
                INSERT INTO admin_alerts (employee_id, message, device_info, is_read) 
                VALUES (?, 'Admin ended break for employee', 'Admin action from dashboard', 0)
            ");
            $alert_stmt->bind_param("i", $emp_id);
            $alert_stmt->execute();

            $conn->commit();
            $_SESSION['success_message'] = "Break ended for employee successfully";
        } else {
            throw new Exception("Cannot end break. Employee might not be on break.");
        }
    } catch (Exception $e) {
        $conn->rollback();
        $_SESSION['error_message'] = "Error ending break: " . $e->getMessage();
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Add a new handler for logging out all employees
if (isset($_POST['logout_all_employees'])) {
    try {
        $conn->begin_transaction();

        // Delete all employee sessions
        $stmt = $conn->query("DELETE FROM session_id");

        // Insert into force_logout table for all employees
        $stmt = $conn->query("INSERT INTO force_logout (user_id) SELECT id FROM employees");

        // Update all active attendances and end breaks
        $stmt = $conn->query("UPDATE attendance SET check_out = NOW() WHERE date = CURRENT_DATE AND check_in IS NOT NULL AND check_out IS NULL");
        $stmt = $conn->query("UPDATE attendance SET break_end = NOW() WHERE date = CURRENT_DATE AND break_start IS NOT NULL AND break_end IS NULL");

        // Update break_schedule for any active breaks
        $stmt = $conn->query("UPDATE break_schedule SET actual_end = NOW() WHERE actual_end IS NULL");

        // Add record to admin_alerts 
        $alert_message = "Admin force logged out all employees";
        $alert_stmt = $conn->prepare("
            INSERT INTO admin_alerts (message, device_info, is_read) 
            VALUES (?, 'Admin action from dashboard', 0)
        ");
        $alert_stmt->bind_param("s", $alert_message);
        $alert_stmt->execute();

        $conn->commit();
        $_SESSION['success_message'] = "All employees have been logged out successfully.";
    } catch (Exception $e) {
        $conn->rollback();
        $_SESSION['error_message'] = "Error logging out all employees: " . $e->getMessage();
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Handler for enabling maintenance mode
if (isset($_POST['enable_maintenance'])) {
    try {
        $reason = isset($_POST['maintenance_reason']) ? $_POST['maintenance_reason'] : 'System update in progress';

        // Create or update maintenance mode settings
        $check_maintenance = $conn->query("SELECT 1 FROM system_settings WHERE setting_key = 'maintenance_mode'");

        if ($check_maintenance->num_rows > 0) {
            $stmt = $conn->prepare("UPDATE system_settings SET setting_value = '1', updated_at = NOW() WHERE setting_key = 'maintenance_mode'");
            $stmt->execute();
        } else {
            $stmt = $conn->prepare("INSERT INTO system_settings (setting_key, setting_value, created_at, updated_at) VALUES ('maintenance_mode', '1', NOW(), NOW())");
            $stmt->execute();
        }

        // Store maintenance reason
        $check_reason = $conn->query("SELECT 1 FROM system_settings WHERE setting_key = 'maintenance_reason'");

        if ($check_reason->num_rows > 0) {
            $stmt = $conn->prepare("UPDATE system_settings SET setting_value = ?, updated_at = NOW() WHERE setting_key = 'maintenance_reason'");
            $stmt->bind_param("s", $reason);
            $stmt->execute();
        } else {
            $stmt = $conn->prepare("INSERT INTO system_settings (setting_key, setting_value, created_at, updated_at) VALUES ('maintenance_reason', ?, NOW(), NOW())");
            $stmt->bind_param("s", $reason);
            $stmt->execute();
        }

        // Add record to admin_alerts
        $alert_message = "Maintenance mode enabled: " . $reason;
        $alert_stmt = $conn->prepare("
            INSERT INTO admin_alerts (message, device_info, is_read) 
            VALUES (?, 'Admin action from dashboard', 0)
        ");
        $alert_stmt->bind_param("s", $alert_message);
        $alert_stmt->execute();

        $_SESSION['success_message'] = "Maintenance mode enabled. Employees cannot log in.";
    } catch (Exception $e) {
        $_SESSION['error_message'] = "Error enabling maintenance mode: " . $e->getMessage();
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Handler for disabling maintenance mode
if (isset($_POST['disable_maintenance'])) {
    try {
        // Update maintenance mode setting
        $stmt = $conn->prepare("UPDATE system_settings SET setting_value = '0', updated_at = NOW() WHERE setting_key = 'maintenance_mode'");
        $stmt->execute();

        // Add record to admin_alerts
        $alert_message = "Maintenance mode disabled";
        $alert_stmt = $conn->prepare("
            INSERT INTO admin_alerts (message, device_info, is_read) 
            VALUES (?, 'Admin action from dashboard', 0)
        ");
        $alert_stmt->bind_param("s", $alert_message);
        $alert_stmt->execute();

        $_SESSION['success_message'] = "Maintenance mode disabled. Employees can now log in.";
    } catch (Exception $e) {
        $_SESSION['error_message'] = "Error disabling maintenance mode: " . $e->getMessage();
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Handler for updating theme
if (isset($_POST['update_theme']) && isset($_POST['theme_color_input'])) {
    $new_theme = $_POST['theme_color_input'];
    if ($new_theme !== 'purple' && $new_theme !== 'red') {
        $new_theme = 'purple'; // Default to purple if invalid value
    }
    
    try {
        // Set the admin theme using helper
        setAdminThemeColor($new_theme, $conn);
        
        // Add to admin alerts
        $alert_message = "Admin theme changed to " . ucfirst($new_theme);
        $stmt = $conn->prepare("INSERT INTO admin_alerts (employee_id, message, device_info, is_read) VALUES (?, ?, 'Admin Action', 0)");
        $stmt->bind_param("is", $_SESSION['admin_id'], $alert_message);
        $stmt->execute();
        
        $_SESSION['success_message'] = "Admin theme updated successfully to " . ucfirst($new_theme);
    } catch (Exception $e) {
        $_SESSION['error_message'] = "Error updating theme: " . $e->getMessage();
    }
    
    // Redirect to the same page with any existing view parameter
    $redirect_url = 'admin.php';
    if (isset($_GET['view'])) {
        $redirect_url .= '?view=' . urlencode($_GET['view']);
    }
    header("Location: " . $redirect_url);
    exit();
}

// Get theme color using the helper function
$theme_color = getAdminThemeColor($conn);

// Get system settings
$company_name = "Fingerprint Attendance";
$maintenance_mode = false;
$maintenance_reason = "System maintenance in progress";
$settings_query = $conn->query("SELECT setting_key, setting_value FROM system_settings WHERE setting_key IN ('company_name', 'maintenance_mode', 'maintenance_reason')");
if ($settings_query && $settings_query->num_rows > 0) {
    while ($row = $settings_query->fetch_assoc()) {
        if ($row['setting_key'] == 'company_name') {
            $company_name = $row['setting_value'];
        } else if ($row['setting_key'] == 'maintenance_mode') {
            $maintenance_mode = ($row['setting_value'] == '1');
        } else if ($row['setting_key'] == 'maintenance_reason') {
            $maintenance_reason = $row['setting_value'];
        }
    }
}

// Get selected employee ID from URL parameter
$selected_employee_id = isset($_GET['employee_id']) ? intval($_GET['employee_id']) : 0;
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    
    <!-- Prevent form resubmission on refresh -->
    <script>
        if (window.history.replaceState) {
            window.history.replaceState(null, null, window.location.href);
        }
    </script>
    
    <title>Admin Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css">
    <style>
        :root {
            /* Theme color variables */
            <?= getThemeCSS($theme_color) ?>
        }
        
        body {
            background-color: #f8f9fa;
            min-height: 100vh;
            position: relative;
            padding-bottom: 30px;
        }

        .dashboard-header {
            background: var(--primary-gradient);
            color: white;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 6px 15px rgba(0, 0, 0, 0.08);
        }

        .dashboard-header h2 {
            margin: 0;
            font-weight: 600;
            font-size: 1.8rem;
        }

        .header-actions .btn {
            padding: 8px 15px;
            border-radius: 8px;
            font-size: 0.9rem;
            font-weight: 500;
            margin-left: 8px;
            box-shadow: 0 3px 5px rgba(0, 0, 0, 0.1);
            transition: all 0.3s;
        }

        .btn-success {
            background-color: #10b981;
            border: none;
        }

        .btn-success:hover {
            background-color: #059669;
            transform: translateY(-2px);
        }

        .btn-danger {
            background-color: #ef4444;
            border: none;
        }

        .btn-danger:hover {
            background-color: #dc2626;
            transform: translateY(-2px);
        }

        .btn-warning {
            background-color: #f59e0b;
            border: none;
            color: white;
        }

        .btn-warning:hover {
            background-color: #d97706;
            color: white;
            transform: translateY(-2px);
        }

        .container {
            max-width: 95%;
            margin: 20px auto;
        }

        .table-container {
            background-color: #fff;
            border-radius: 12px;
            box-shadow: 0 6px 15px rgba(0, 0, 0, 0.08);
            padding: 15px;
            margin-bottom: 30px;
            overflow: hidden;
        }

        .table {
            margin: 0;
        }

        .table td,
        .table th {
            padding: 12px 15px;
            vertical-align: middle;
            font-size: 0.9rem;
        }

        .table th {
            font-weight: 600;
            background: var(--primary-gradient);
            color: white;
            white-space: nowrap;
            border: none;
        }

        .table-striped tbody tr:nth-of-type(odd) {
            background-color: rgba(0, 0, 0, .02);
        }

        .break-input {
            width: 70px;
            display: inline-block;
            margin-right: 8px;
        }

        .btn-group {
            gap: 5px;
            flex-wrap: wrap;
        }

        .btn-group .btn {
            margin-bottom: 5px;
            font-size: 0.8rem;
            padding: 6px 10px;
        }

        .badge {
            font-size: 0.75rem;
            padding: 5px 8px;
            border-radius: 6px;
        }

        .table-responsive {
            padding: 0;
            border-radius: 12px;
            overflow: hidden;
            width: 100%;
        }

        .alert {
            border-radius: 10px;
            padding: 12px 15px;
            margin-bottom: 20px;
            border: none;
            font-size: 0.9rem;
        }

        .alert-success {
            background-color: #d1fae5;
            color: #065f46;
        }

        .alert-danger {
            background-color: #fee2e2;
            color: #b91c1c;
        }

        .form-control {
            border-radius: 8px;
            font-size: 0.9rem;
        }

        .modal-content {
            border-radius: 12px;
            border: none;
            overflow: hidden;
        }

        .modal-header {
            background: var(--primary-gradient);
            color: white;
            border: none;
            padding: 15px 20px;
        }

        .modal-footer {
            border-top: 1px solid #eee;
            padding: 12px 20px;
        }

        .btn-sm {
            padding: 5px 10px;
            font-size: 0.8rem;
        }

        .btn-primary {
            background: var(--primary-gradient);
            border: none;
        }

        .btn-primary:hover {
            background: linear-gradient(135deg, var(--primary-dark) 0%, var(--secondary-color) 100%);
        }

        .password-cell {
            font-family: monospace;
            background-color: #f8f9fa;
            padding: 2px 6px;
            border-radius: 4px;
            border: 1px solid #dee2e6;
        }

        /* Table Responsiveness improvements */
        @media (max-width: 1200px) {

            .table td,
            .table th {
                padding: 10px 8px;
            }
        }

        @media (max-width: 992px) {
            .dashboard-header {
                flex-direction: column;
                align-items: flex-start !important;
            }

            .header-actions {
                margin-top: 15px;
                width: 100%;
                display: flex;
                flex-wrap: wrap;
                gap: 8px;
            }

            .header-actions .btn {
                margin-left: 0;
                margin-bottom: 5px;
                flex: 1 1 auto;
            }

            .table th,
            .table td {
                padding: 10px 8px;
                font-size: 0.85rem;
            }

            .table {
                min-width: 800px;
            }

            .scroll-indicator {
                display: block;
                text-align: center;
                padding: 5px 0;
                font-size: 0.8rem;
                margin-bottom: 10px;
                color: #6a11cb;
            }
        }

        @media (max-width: 768px) {
            .container {
                max-width: 100%;
                padding: 0 10px;
            }

            .dashboard-header h2 {
                font-size: 1.5rem;
            }

            .table-container {
                padding: 10px;
                position: relative;
            }

            .table-responsive {
                overflow-x: auto;
                -webkit-overflow-scrolling: touch;
                /* Smooth scrolling on iOS */
                            scrollbar-width: thin;
            /* Firefox */
            scrollbar-color: var(--primary-color) #f1f1f1;
            /* Firefox */
            }

            /* Customize scrollbar for Webkit browsers */
            .table-responsive::-webkit-scrollbar {
                height: 6px;
            }

            .table-responsive::-webkit-scrollbar-track {
                background: #f1f1f1;
                border-radius: 3px;
            }

            .table-responsive::-webkit-scrollbar-thumb {
                background: var(--primary-color);
                background: var(--primary-gradient);
                border-radius: 3px;
            }

            .table th,
            .table td {
                padding: 8px 6px;
                font-size: 0.8rem;
            }

            .btn-group .btn {
                font-size: 0.75rem;
                padding: 4px 8px;
            }

            .badge {
                font-size: 0.7rem;
                padding: 4px 6px;
            }

            .table {
                min-width: 700px;
            }

            .scroll-indicator {
                display: block;
                color: var(--primary-color);
                font-weight: 500;
                animation: pulse 2s infinite;
            }

            @keyframes pulse {
                0% {
                    opacity: 0.6;
                }

                50% {
                    opacity: 1;
                }

                100% {
                    opacity: 0.6;
                }
            }
        }

        /* Hide certain columns on mobile */
        @media (max-width: 576px) {
            .table {
                min-width: 650px;
            }

            .mobile-hide {
                display: none;
            }

            .table th,
            .table td {
                padding: 6px 4px;
                font-size: 0.75rem;
            }

            /* Enhanced scrolling indicators for very small screens */
            .table-container:before,
            .table-container:after {
                content: "";
                position: absolute;
                top: 50%;
                width: 20px;
                height: 40px;
                margin-top: -20px;
                background-size: contain;
                background-repeat: no-repeat;
                opacity: 0.5;
                z-index: 1;
                pointer-events: none;
            }

            .table-container:before {
                left: 5px;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' fill='<?= urlencode($theme_color === 'red' ? '%23cb1111' : '%236a11cb') ?>' class='bi bi-arrow-left-circle' viewBox='0 0 16 16'%3E%3Cpath fill-rule='evenodd' d='M1 8a7 7 0 1 0 14 0A7 7 0 0 0 1 8zm15 0A8 8 0 1 1 0 8a8 8 0 0 1 16 0zm-4.5-.5a.5.5 0 0 1 0 1H5.707l2.147 2.146a.5.5 0 0 1-.708.708l-3-3a.5.5 0 0 1 0-.708l3-3a.5.5 0 1 1 .708.708L5.707 7.5H11.5z'/%3E%3C/svg%3E");
            }

            .table-container:after {
                right: 5px;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' fill='<?= urlencode($theme_color === 'red' ? '%23cb1111' : '%236a11cb') ?>' class='bi bi-arrow-right-circle' viewBox='0 0 16 16'%3E%3Cpath fill-rule='evenodd' d='M1 8a7 7 0 1 0 14 0A7 7 0 0 0 1 8zm15 0A8 8 0 1 1 0 8a8 8 0 0 1 16 0zM4.5 7.5a.5.5 0 0 0 0 1h5.793l-2.147 2.146a.5.5 0 0 0 .708.708l3-3a.5.5 0 0 0 0-.708l-3-3a.5.5 0 1 0-.708.708L10.293 7.5H4.5z'/%3E%3C/svg%3E");
            }
        }

        .scroll-indicator {
            display: block;
            text-align: center;
            padding: 8px 0;
            margin-bottom: 10px;
            color: white;
            background: var(--primary-gradient);
            border-radius: 8px;
            font-weight: 500;
            cursor: pointer;
            box-shadow: 0 3px 5px rgba(0, 0, 0, 0.1);
            transition: all 0.3s;
        }

        .scroll-indicator:hover {
            background: linear-gradient(135deg, var(--primary-dark) 0%, var(--secondary-color) 100%);
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
        }

        .scroll-indicator i {
            margin-right: 5px;
            animation: bounce 2s infinite;
        }

        @keyframes bounce {

            0%,
            20%,
            50%,
            80%,
            100% {
                transform: translateX(0);
            }

            40% {
                transform: translateX(-10px);
            }

            60% {
                transform: translateX(-5px);
            }
        }

        /* Dashboard Stats Cards */
        .stat-card {
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            padding: 25px;
            height: 100%;
            transition: transform 0.3s ease;
            border: none;
            display: flex;
            flex-direction: column;
            align-items: center;
            text-align: center;
        }

        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 15px rgba(0, 0, 0, 0.1);
        }

        .stat-card .icon {
            font-size: 2.5rem;
            margin-bottom: 20px;
            color: white;
            background: var(--primary-gradient);
            width: 80px;
            height: 80px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            margin-top: -40px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
        }

        .stat-card .number {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 5px;
            color: var(--primary-color);
        }

        .stat-card .title {
            color: #6c757d;
            font-size: 1rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 500;
        }

        .admin-action {
            display: block;
            border-radius: 10px;
            padding: 20px;
            background: white;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            transition: all 0.3s ease;
            margin-bottom: 15px;
            color: var(--primary-color);
            text-decoration: none;
            border-left: 5px solid var(--primary-color);
        }

        .admin-action:hover {
            transform: translateX(5px);
            box-shadow: 0 6px 8px rgba(0, 0, 0, 0.1);
            color: var(--secondary-color);
        }

        .admin-action .bi {
            font-size: 1.5rem;
            margin-right: 10px;
            vertical-align: middle;
        }

        .view-toggle-btn {
            padding: 8px 16px;
            background: rgba(255, 255, 255, 0.2);
            color: white;
            border: 1px solid rgba(255, 255, 255, 0.3);
            border-radius: 8px;
            transition: all 0.3s;
        }

        .view-toggle-btn:hover {
            background: rgba(255, 255, 255, 0.3);
            transform: translateY(-2px);
        }

        .view-toggle-btn .bi {
            margin-right: 5px;
        }

        /* Break timer styles */
        .break-timer-element {
            font-family: monospace;
            font-size: 0.9rem;
            padding: 0.4rem 0.7rem;
            border-radius: 6px;
            font-weight: 600;
            transition: all 0.2s ease;
            min-width: 70px;
            text-align: center;
        }

        .break-timer-container {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 10px;
            background: rgba(255, 193, 7, 0.1);
            padding: 8px 10px;
            border-radius: 8px;
        }

        .modal-custom-header {
            background-image: var(--primary-gradient);
            color: white;
            border-radius: 12px 12px 0 0;
            padding: 15px 20px;
        }

        /* From Uiverse.io by jeremyssocial */
        @keyframes blinkCursor {
            50% {
                border-right-color: transparent;
            }
        }

        @keyframes typeAndDelete {

            0%,
            10% {
                width: 0;
            }

            45%,
            55% {
                width: 6.2em;
            }

            /* adjust width based on content */
            90%,
            100% {
                width: 0;
            }
        }

        .terminal-loader {
            border: 0.1em solid #333;
            background-color: #1a1a1a;
            color: #0f0;
            font-family: "Courier New", Courier, monospace;
            font-size: 1em;
            padding: 1em 2em;
            width: 12em;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
            border-radius: 4px;
            position: relative;
            overflow: hidden;
            box-sizing: border-box;
        }

        .terminal-header {
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1.5em;
            background-color: #333;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
            padding: 0 0.4em;
            box-sizing: border-box;
        }

        .terminal-controls {
            float: right;
        }

        .control {
            display: inline-block;
            width: 0.6em;
            height: 0.6em;
            margin-left: 0.4em;
            border-radius: 50%;
            background-color: #777;
        }

        .control.close {
            background-color: #e33;
        }

        .control.minimize {
            background-color: #ee0;
        }

        .control.maximize {
            background-color: #0b0;
        }

        .terminal-title {
            float: left;
            line-height: 1.5em;
            color: #eee;
        }

        .text {
            display: inline-block;
            white-space: nowrap;
            overflow: hidden;
            border-right: 0.2em solid green;
            /* Cursor */
            animation:
                typeAndDelete 4s steps(11) infinite,
                blinkCursor 0.5s step-end infinite alternate;
            margin-top: 1.5em;
        }

        .button-css {
            padding: 11px 12px;
            margin-left: 7px;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            font-weight: 500;
            color: white;
            background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%);
            border: none;
            border-radius: 8px;
            box-shadow: 0px 8px 15px rgba(0, 0, 0, 0.1);
            transition: all 0.3s ease 0s;
            cursor: pointer;
            outline: none;
        }

        .button-css:hover {
            background-color: #2575fc;
            box-shadow: 0px 15px 20px rgba(46, 229, 157, 0.4);
            color: #fff;
            transform: translateY(-7px);
        }

        .button-css:active {
            transform: translateY(-1px);
        }

        /* Sortable styles */
        .drag-handle {
            cursor: grab;
            color: #6a11cb;
            padding: 8px;
            border-radius: 4px;
            transition: all 0.2s;
            width: 40px;
            height: 40px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .drag-handle:hover {
            background-color: rgba(106, 17, 203, 0.1);
        }

        .drag-handle:active {
            cursor: grabbing;
        }

        .sortable-ghost {
            opacity: 0.4;
            background-color: #f8f9fa;
        }

        .sortable-chosen {
            background-color: #e9ecef;
            box-shadow: 0 0 8px rgba(106, 17, 203, 0.3);
        }

        .sortable-drag {
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.15);
        }

        #employeesList li {
            transition: all 0.3s;
            border-left: 3px solid transparent;
            padding: 12px 15px;
            margin-bottom: 8px;
        }

        #employeesList li:hover {
            border-left-color: #6a11cb;
            background-color: rgba(106, 17, 203, 0.05);
        }

        .order-number {
            background: var(--primary-gradient);
            box-shadow: 0 3px 5px rgba(0, 0, 0, 0.2);
            transition: all 0.3s;
        }

        #employeesList li:hover .order-number {
            transform: scale(1.1);
        }

        /* Attendance History Styles */
        .modal-dialog-scrollable {
            max-height: 90vh;
        }

        .nav-tabs .nav-link {
            color: #6c757d;
            font-weight: 500;
            padding: 0.75rem 1.25rem;
            border-radius: 0;
            transition: all 0.2s;
        }

        .nav-tabs .nav-link.active {
            color: var(--primary-color);
            border-bottom: 3px solid var(--primary-color);
            background: linear-gradient(to bottom, rgba(var(--primary-color), 0.05), transparent);
        }

        .nav-tabs .nav-link:hover:not(.active) {
            border-color: transparent;
            background-color: rgba(106, 17, 203, 0.05);
        }

        .tab-content {
            border: 1px solid #dee2e6;
            border-top: none;
        }

        .attendance-summary-card {
            border: none;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        .attendance-summary-card .card-header {
            background: var(--primary-gradient);
            padding: 1rem;
            color: white;
            font-weight: 600;
        }

        .attendance-summary-card .card-body {
            padding: 1.5rem;
        }

        .attendance-stat-card {
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.05);
            transition: all 0.3s;
        }

        .attendance-stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }
        
        /* License Card Styles */
        .license-info-card {
            background: linear-gradient(135deg, #ffffff, #f5f7ff);
            border-radius: 10px;
            overflow: hidden;
            border-left: 4px solid var(--primary-color);
            transition: all 0.3s ease;
        }
        
        .license-info-card:hover {
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1);
            transform: translateY(-3px);
        }
        
        .license-countdown-wrapper {
            background: rgba(0, 0, 0, 0.03);
            padding: 10px 20px;
            border-radius: 10px;
        }
        
        .license-countdown {
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
        }
        
        .time-block {
            display: flex;
            flex-direction: column;
            align-items: center;
            min-width: 60px;
        }
        
        .time-block span {
            font-size: 24px;
            font-weight: 700;
            color: var(--primary-color);
        }
        
        .time-block small {
            font-size: 12px;
            color: #666;
        }
        
        .time-separator {
            font-size: 24px;
            font-weight: 700;
            color: #ccc;
            margin: 0 5px;
        }
    </style>
</head>

<body>
    <div class="container py-4">
        <div class="dashboard-header d-flex justify-content-between align-items-center">
            <!-- From Uiverse.io by jeremyssocial -->
            <div class="terminal-loader">
                <div class="terminal-header">
                    <div class="terminal-title">Admin Dashboard</div>
                </div>
                <div class="text">Godzilla...</div>
            </div>

            <div class="header-actions">
                <a href="?view=<?= $view_mode === 'dashboard' ? 'employees' : 'dashboard' ?>" class="btn button-css">
                    <?php if ($view_mode === 'dashboard'): ?>
                        <i class="bi bi-people-fill"></i> Employee List
                    <?php else: ?>
                        <i class="bi bi-grid-fill"></i> Dashboard
                    <?php endif; ?>
                </a>
                <a href="add_employee.php" class="btn btn-success">
                    <i class="bi bi-person-plus-fill me-1"></i> Add Employee
                </a>
                <a href="admin_logout.php" class="btn btn-danger">
                    <i class="bi bi-box-arrow-right me-1"></i> Logout
                </a>
            </div>
        </div>

        <?php if ($message): ?>
            <div class="alert alert-success alert-dismissible fade show">
                <i class="bi bi-check-circle-fill me-2"></i>
                <?= htmlspecialchars($message) ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>

        <?php if ($error_message): ?>
            <div class="alert alert-danger alert-dismissible fade show">
                <i class="bi bi-exclamation-triangle-fill me-2"></i>
                <?= htmlspecialchars($error_message) ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>

        <?php if ($view_mode === 'dashboard'): ?>
            <!-- Dashboard View -->
            <!-- Stats Cards -->
            <div class="row mb-4 pt-5">
                <?php if ($is_suspended): ?>
                <div class="col-12 mb-4">
                    <div class="alert alert-warning alert-dismissible fade show" role="alert">
                        <h4 class="alert-heading"><i class="bi bi-exclamation-triangle-fill me-2"></i>License Suspended</h4>
                        <p>Your license has been temporarily suspended. Please contact the system administrator for more information.</p>
                        <hr>
                        <p class="mb-0">Some features may be limited until the license is reactivated.</p>
                    </div>
                </div>
                <?php endif; ?>
                <!-- License Info Card - Add New Card -->
                <div class="col-md-12 mb-4">
                    <div class="card border-0 shadow-sm license-info-card">
                        <div class="card-body d-flex justify-content-between align-items-center">
                            <div>
                                <div class="d-flex align-items-center mb-2">
                                    <i class="bi bi-shield-check me-2" style="font-size: 24px; color: var(--primary-color);"></i>
                                    <h5 class="mb-0">License Information</h5>
                                </div>
                                <p class="text-muted mb-0">
                                    License expires on: <strong><?= date('d-m-Y', strtotime($license_result['end_date'])) ?></strong>
                                </p>
                                <?php
                                $now = new DateTime();
                                $end = new DateTime($license_result['end_date']);
                                $interval = $now->diff($end);
                                $daysLeft = $interval->days;
                                $status = 'success';
                                if ($daysLeft <= 30) $status = 'warning';
                                if ($daysLeft <= 7) $status = 'danger';
                                ?>
                                <div class="mt-2">
                                    <div class="badge bg-<?= $status ?> px-3 py-2">
                                        <i class="bi bi-calendar-event me-1"></i>
                                        <?= $daysLeft ?> days remaining
                                    </div>
                                </div>
                            </div>
                            <div class="d-none d-md-block">
                                <div class="license-countdown-wrapper">
                                    <div class="license-countdown" data-end="<?= $license_result['end_date'] ?>">
                                        <div class="time-block">
                                            <span class="days">00</span>
                                            <small>days</small>
                                        </div>
                                        <div class="time-separator">:</div>
                                        <div class="time-block">
                                            <span class="hours">00</span>
                                            <small>hours</small>
                                        </div>
                                        <div class="time-separator">:</div>
                                        <div class="time-block">
                                            <span class="minutes">00</span>
                                            <small>minutes</small>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="col-md-3 mb-3">
                    <div class="stat-card bg-white">
                        <div class="icon">
                            <i class="bi bi-people-fill"></i>
                        </div>
                        <p class="number"><?= $employeesCount ?></p>
                        <p class="title">Total Employees</p>
                    </div>
                </div>

                <div class="col-md-3 mb-3">
                    <div class="stat-card bg-white">
                        <div class="icon">
                            <i class="bi bi-person-check-fill"></i>
                        </div>
                        <p class="number"><?= $checkedInCount ?></p>
                        <p class="title">Checked In Today</p>
                    </div>
                </div>

                <div class="col-md-3 mb-3">
                    <div class="stat-card bg-white">
                        <div class="icon">
                            <i class="bi bi-cup-hot-fill"></i>
                        </div>
                        <p class="number"><?= $onBreakCount ?></p>
                        <p class="title">On Break</p>
                    </div>
                </div>

                <div class="col-md-3 mb-3">
                    <div class="stat-card bg-white">
                        <div class="icon">
                            <i class="bi bi-bell-fill"></i>
                        </div>
                        <p class="number"><?= $alertsCount ?></p>
                        <p class="title">Unread Alerts</p>
                    </div>
                </div>
            </div>

            <div class="row">
                <div class="col-md-6 mb-4">
                    <h4 class="mb-3">Admin Actions</h4>

                    <a href="admin_alerts.php" class="admin-action">
                        <i class="bi bi-bell-fill"></i> View System Alerts
                        <?php if ($alertsCount > 0): ?>
                            <span class="badge bg-danger float-end"><?= $alertsCount ?></span>
                        <?php endif; ?>
                    </a>

                    <a href="?view=employees" class="admin-action">
                        <i class="bi bi-people-fill"></i> Manage Employees
                    </a>

                    <a href="attendance_reports.php" class="admin-action">
                        <i class="bi bi-calendar-check-fill"></i> Attendance Reports
                    </a>

                    <a href="#systemSettingsModal" data-bs-toggle="modal" class="admin-action">
                        <i class="bi bi-gear-fill"></i> System Settings
                    </a>
                    
                    <!-- Add new button for System Stats -->
                    <a href="#systemStatsModal" data-bs-toggle="modal" class="admin-action">
                        <i class="bi bi-bar-chart-fill"></i> System Statistics
                    </a>
                </div>

                <div class="col-md-6 mb-4">
                    <h4 class="mb-3">Recent Activity</h4>

                    <div class="d-flex justify-content-end mb-2">
                        <form method="POST" action="" class="me-2">
                            <button type="submit" name="mark_all_read" class="btn btn-sm btn-outline-primary" onclick="return confirm('Are you sure you want to mark all alerts as read? This action cannot be undone.')">
                                <i class="bi bi-check-all"></i> Mark all as read
                            </button>
                        </form>
                        <form method="POST" action="">
                            <button type="submit" name="clear_all_activity" class="btn btn-sm btn-outline-danger" onclick="return confirm('Are you sure you want to delete all activity? This action cannot be undone.')">
                                <i class="bi bi-trash"></i> Delete All
                            </button>
                        </form>
                    </div>

                    <div class="list-group">
                        <?php
                        // Get recent activity from admin_alerts
                        $activityQuery = $conn->query("
                        SELECT a.*, e.name as employee_name 
                        FROM admin_alerts a 
                        LEFT JOIN employees e ON a.employee_id = e.id 
                        ORDER BY a.timestamp DESC 
                        LIMIT 5
                    ");

                        if ($activityQuery && $activityQuery->num_rows > 0) {
                            while ($activity = $activityQuery->fetch_assoc()) {
                                $isUnread = $activity['is_read'] == 0;
                                $employeeName = $activity['employee_name'] ? htmlspecialchars($activity['employee_name']) : 'Unknown';

                                echo '<a href="admin_alerts.php" class="list-group-item list-group-item-action' . ($isUnread ? ' bg-light' : '') . '">';
                                echo '<div class="d-flex w-100 justify-content-between">';
                                echo '<h6 class="mb-1">' . htmlspecialchars($activity['message']) . '</h6>';
                                echo '<small>' . date('h:i A', strtotime($activity['timestamp'])) . '</small>';
                                echo '</div>';
                                echo '<p class="mb-1">Employee: ' . $employeeName . '</p>';
                                echo '<small>' . date('M j, Y', strtotime($activity['timestamp'])) . '</small>';
                                if ($isUnread) {
                                    echo '<span class="badge bg-danger float-end">New</span>';
                                }
                                echo '</a>';
                            }
                        } else {
                            echo '<div class="list-group-item">No recent activity found</div>';
                        }
                        ?>
                    </div>
                </div>
            </div>
        <?php else: ?>
            <!-- Employee List View -->
            <div class="table-container">
                <!-- Scroll indicator for small screens -->
                <div class="scroll-indicator d-block d-lg-none" id="scrollIndicator">
                    <i class="bi bi-arrow-left-right"></i> Swipe horizontally to view all data
                </div>
                <div class="table-responsive" id="employeeTableContainer">
                    <table class="table table-bordered table-striped mb-0">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Name</th>
                                <th>Email</th>
                                <th class="mobile-hide">Password</th>
                                <th>Status</th>
                                <th class="mobile-hide">Online</th>
                                <th class="mobile-hide">Check In</th>
                                <th>Break</th>
                                <th class="mobile-hide">Check Out</th>
                                <th class="text-center">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php
                            if ($employees):
                                $serial = 1;
                                while ($emp = $employees->fetch_assoc()) {
                                    $att = $attendance_data[$emp['id']] ?? null;
                                    $is_online = in_array($emp['id'], $logged_in_employees);
                                    $is_checked_out = $att && $att['check_out'];
                            ?>
                                    <tr>
                                        <td><?= $serial++ ?></td>
                                        <td><?= htmlspecialchars($emp['name']) ?></td>
                                        <td><?= htmlspecialchars($emp['email']) ?></td>
                                        <td class="mobile-hide">
                                            <?php if ($emp['password']): ?>
                                                <span class="badge bg-info"><?= htmlspecialchars($emp['password']) ?></span>
                                            <?php else: ?>
                                                <span class="badge bg-secondary">---</span>
                                            <?php endif; ?>
                                        </td>
                                        <td><?= getEmployeeStatus($att) ?></td>
                                        <td class="mobile-hide">
                                            <?php if ($is_online): ?>
                                                <span class="badge bg-success">Online</span>
                                            <?php else: ?>
                                                <span class="badge bg-secondary">Offline</span>
                                            <?php endif; ?>
                                        </td>
                                        <td class="mobile-hide"><?= $att && $att['check_in'] ? date('h:i:s', strtotime($att['check_in'])) : '---' ?></td>
                                        <td>
                                            <?= getBreakStatus($att, $emp['id'], $is_checked_out) ?>
                                            <?php if ($att && $att['check_in'] && !$att['check_out']): ?>
                                                <div class="mt-2">
                                                    <a href="break_manage.php?id=<?= $emp['id'] ?>" class="btn btn-sm btn-outline-info">
                                                        <i class="bi bi-sliders"></i> Advanced
                                                    </a>
                                                </div>
                                            <?php endif; ?>
                                        </td>
                                        <td class="mobile-hide"><?= $att && $att['check_out'] ? date('h:i:s', strtotime($att['check_out'])) : '---' ?></td>
                                        <td class="text-center">
                                            <div class="btn-group">
                                                <a href="edit_employee.php?id=<?= $emp['id'] ?>" class="btn btn-sm btn-primary">
                                                    <i class="bi bi-pencil-square"></i> Edit
                                                </a>
                                                <button type="button" class="btn btn-sm btn-info" data-bs-toggle="modal" data-bs-target="#attendanceHistoryModal<?= $emp['id'] ?>">
                                                    <i class="bi bi-calendar-check"></i> History
                                                </button>
                                                <button class="btn btn-sm btn-danger" onclick="deleteEmployee(<?= $emp['id'] ?>)">
                                                    <i class="bi bi-trash"></i> Delete
                                                </button>
                                                <?php if ($is_online): ?>
                                                    <div class="dropdown d-inline">
                                                        <button class="btn btn-sm btn-secondary dropdown-toggle" type="button" id="employeeActionsDropdown<?= $emp['id'] ?>" data-bs-toggle="dropdown" aria-expanded="false">
                                                            <i class="bi bi-gear"></i> Actions
                                                        </button>
                                                        <ul class="dropdown-menu" aria-labelledby="employeeActionsDropdown<?= $emp['id'] ?>">
                                                            <li>
                                                                <form method="POST" action="" style="display:inline;">
                                                                    <input type="hidden" name="id" value="<?= $emp['id'] ?>">
                                                                    <button type="submit" name="logout_employee" class="dropdown-item" onclick="return confirm('Are you sure you want to logout this employee?')">
                                                                        <i class="bi bi-box-arrow-left"></i> Logout Employee
                                                                    </button>
                                                                </form>
                                                            </li>
                                                            <?php if ($att && $att['check_in'] && !$att['check_out']): ?>
                                                                <li>
                                                                    <form method="POST" action="" style="display:inline;">
                                                                        <input type="hidden" name="id" value="<?= $emp['id'] ?>">
                                                                        <button type="submit" name="force_checkout" class="dropdown-item" onclick="return confirm('Force checkout for this employee? This will bypass the minimum hours requirement.')">
                                                                            <i class="bi bi-door-open"></i> Force Checkout
                                                                        </button>
                                                                    </form>
                                                                </li>
                                                                <li>
                                                                    <button type="button" class="dropdown-item" data-bs-toggle="modal" data-bs-target="#startBreakModal<?= $emp['id'] ?>">
                                                                        <i class="bi bi-cup-hot"></i> Manage Break
                                                                    </button>
                                                                </li>
                                                                <li>
                                                                    <a href="break_manage.php?id=<?= $emp['id'] ?>" class="dropdown-item">
                                                                        <i class="bi bi-sliders"></i> Break Details
                                                                    </a>
                                                                </li>
                                                                <li>
                                                                    <button type="button" class="dropdown-item" data-bs-toggle="modal" data-bs-target="#attendanceHistoryModal<?= $emp['id'] ?>">
                                                                        <i class="bi bi-calendar-check"></i> Attendance History
                                                                    </button>
                                                                </li>
                                                            <?php endif; ?>
                                                        </ul>
                                                    </div>
                                                <?php endif; ?>
                                            </div>
                                        </td>
                                    </tr>
                            <?php
                                }
                            endif;
                            ?>
                        </tbody>
                    </table>
                </div>
            </div>
        <?php endif; ?>

        <!-- Access Attempts Modal -->
        <div class="modal fade" id="accessAttemptsModal" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title"><i class="bi bi-shield-exclamation me-2"></i>Unauthorized Access Attempts</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body p-0">
                        <div class="table-responsive">
                            <table class="table table-striped table-bordered mb-0">
                                <thead>
                                    <tr>
                                        <th>Time</th>
                                        <th>Username</th>
                                        <th>IP Address</th>
                                        <th>Device Details</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (!empty($access_attempts)): ?>
                                        <?php foreach ($access_attempts as $attempt): ?>
                                            <tr>
                                                <td><?= htmlspecialchars(date('Y-m-d h:i:s', strtotime($attempt['attempt_time']))) ?></td>
                                                <td><?= htmlspecialchars($attempt['username']) ?></td>
                                                <td><?= htmlspecialchars($attempt['ip_address']) ?></td>
                                                <td>
                                                    <strong>Browser:</strong> <?= htmlspecialchars($attempt['user_agent']) ?><br>
                                                    <strong>Details:</strong> <?= htmlspecialchars($attempt['device_details']) ?>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    <?php else: ?>
                                        <tr>
                                            <td colspan="4" class="text-center">No unauthorized access attempts found.</td>
                                        </tr>
                                    <?php endif; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <form method="POST" class="me-auto">
                            <button type="submit" name="clear_history" class="btn btn-danger" onclick="return confirm('Are you sure you want to clear all access history? This action cannot be undone.')">
                                <i class="bi bi-trash"></i> Clear History
                            </button>
                        </form>
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Break Management Modals -->
    <?php
    if ($employees):
        $employees->data_seek(0); // Reset result pointer
        while ($emp = $employees->fetch_assoc()):
            $att = $attendance_data[$emp['id']] ?? null;
            $is_checked_out = $att && $att['check_out'];

            // Only create modals for employees who are checked in but not checked out
            if ($att && $att['check_in'] && !$att['check_out']):
    ?>
                <!-- Start Break Modal -->
                <div class="modal fade" id="startBreakModal<?= $emp['id'] ?>" tabindex="-1" aria-labelledby="startBreakModalLabel<?= $emp['id'] ?>" aria-hidden="true">
                    <div class="modal-dialog">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title" id="startBreakModalLabel<?= $emp['id'] ?>">
                                    <i class="bi bi-cup-hot me-2"></i>Manage Break for <?= htmlspecialchars($emp['name']) ?>
                                </h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                            </div>
                            <div class="modal-body">
                                <div class="text-center mb-4">
                                    <img src="https://via.placeholder.com/100" class="rounded-circle mb-3" alt="<?= htmlspecialchars($emp['name']) ?>">
                                    <h5><?= htmlspecialchars($emp['name']) ?></h5>
                                    <div class="badge bg-primary mb-2">Employee #<?= $emp['id'] ?></div>

                                    <?php if ($att['break_start'] && !$att['break_end']): ?>
                                        <div class="alert alert-warning">
                                            <i class="bi bi-exclamation-triangle-fill me-2"></i>
                                            This employee is currently on a break
                                        </div>
                                    <?php elseif (!$att['break_start'] || ($att['break_start'] && $att['break_end'])): ?>
                                        <div class="alert alert-info">
                                            <i class="bi bi-info-circle-fill me-2"></i>
                                            You can start a new break for this employee
                                        </div>
                                    <?php endif; ?>
                                </div>

                                <?php if (!$att['break_start'] || ($att['break_start'] && $att['break_end'])): ?>
                                    <form method="POST" action="">
                                        <input type="hidden" name="id" value="<?= $emp['id'] ?>">

                                        <div class="mb-3">
                                            <label for="breakDuration<?= $emp['id'] ?>" class="form-label">Break Duration (minutes)</label>
                                            <div class="input-group">
                                                <input type="number" class="form-control" id="breakDuration<?= $emp['id'] ?>" name="break_minutes" min="5" max="60" value="15" required>
                                                <span class="input-group-text">minutes</span>
                                            </div>
                                            <small class="text-muted">Set how long the break should last (5-60 minutes)</small>
                                        </div>

                                        <div class="mb-3">
                                            <label class="form-label">Break Type</label>
                                            <div class="form-check">
                                                <input class="form-check-input" type="radio" name="break_type" id="lunchBreak<?= $emp['id'] ?>" value="lunch" checked>
                                                <label class="form-check-label" for="lunchBreak<?= $emp['id'] ?>">
                                                    <i class="bi bi-cup-hot me-1"></i> Lunch Break
                                                </label>
                                            </div>
                                            <div class="form-check">
                                                <input class="form-check-input" type="radio" name="break_type" id="restBreak<?= $emp['id'] ?>" value="rest">
                                                <label class="form-check-label" for="restBreak<?= $emp['id'] ?>">
                                                    <i class="bi bi-clock-history me-1"></i> Rest Break
                                                </label>
                                            </div>
                                        </div>

                                        <div class="d-grid gap-2">
                                            <button type="submit" name="add_break" class="btn btn-warning">
                                                <i class="bi bi-cup-hot me-2"></i> Start Break Now
                                            </button>
                                        </div>
                                    </form>
                                <?php else: ?>
                                    <div class="text-center">
                                        <p>To end the current break, please use the End Break button.</p>
                                        <form method="POST" action="">
                                            <input type="hidden" name="id" value="<?= $emp['id'] ?>">
                                            <button type="submit" name="end_break" class="btn btn-danger">
                                                <i class="bi bi-cup me-2"></i> End Break Now
                                            </button>
                                        </form>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- End Break Modal -->
                <?php if ($att['break_start'] && !$att['break_end']): ?>
                    <div class="modal fade" id="endBreakModal<?= $emp['id'] ?>" tabindex="-1" aria-labelledby="endBreakModalLabel<?= $emp['id'] ?>" aria-hidden="true">
                        <div class="modal-dialog">
                            <div class="modal-content">
                                <div class="modal-header bg-danger text-white">
                                    <h5 class="modal-title" id="endBreakModalLabel<?= $emp['id'] ?>">
                                        <i class="bi bi-cup me-2"></i>End Break for <?= htmlspecialchars($emp['name']) ?>
                                    </h5>
                                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                                </div>
                                <div class="modal-body">
                                    <div class="text-center mb-4">
                                        <div class="break-timer-container mb-3">
                                            <i class="bi bi-cup-hot-fill text-warning" style="font-size: 2.5rem;"></i>
                                            <?php
                                            // Get break details
                                            $stmt = $conn->prepare("
                                            SELECT scheduled_end, break_start, break_type
                                            FROM break_schedule 
                                            WHERE employee_id = ? 
                                            AND actual_end IS NULL 
                                            ORDER BY id DESC 
                                            LIMIT 1
                                        ");
                                            $stmt->bind_param("i", $emp['id']);
                                            $stmt->execute();
                                            $result = $stmt->get_result();
                                            $break_details = $result->fetch_assoc();

                                            if ($break_details):
                                                $break_start = new DateTime($break_details['break_start']);
                                                $now = new DateTime();
                                                $scheduled_end = new DateTime($break_details['scheduled_end']);
                                                $elapsed = $break_start->diff($now);
                                                $elapsed_seconds = ($elapsed->h * 3600) + ($elapsed->i * 60) + $elapsed->s;
                                                $break_type = ucfirst($break_details['break_type'] ?? 'lunch');
                                            ?>
                                                <div class="break-timer-element break-timer-lg badge bg-danger"
                                                    data-start-time="<?= $break_details['break_start'] ?>"
                                                    data-elapsed-seconds="<?= $elapsed_seconds ?>"
                                                    style="font-size: 1.5rem; padding: 10px 15px;">
                                                    <?= floor($elapsed_seconds / 60) ?>m <?= $elapsed_seconds % 60 ?>s
                                                </div>
                                        </div>

                                        <h5 class="mt-3">End <?= $break_type ?> Break for <?= htmlspecialchars($emp['name']) ?></h5>

                                        <div class="card border-info mb-3 mt-3">
                                            <div class="card-header bg-info text-white">
                                                <i class="bi bi-info-circle me-2"></i>Break Details
                                            </div>
                                            <div class="card-body text-start">
                                                <div class="d-flex justify-content-between mb-2">
                                                    <span><i class="bi bi-clock me-1"></i> Started:</span>
                                                    <strong><?= $break_start->format('h:i:s A') ?></strong>
                                                </div>
                                                <div class="d-flex justify-content-between mb-2">
                                                    <span><i class="bi bi-alarm me-1"></i> Scheduled End:</span>
                                                    <strong><?= $scheduled_end->format('h:i:s A') ?></strong>
                                                </div>
                                                <div class="d-flex justify-content-between mb-2">
                                                    <span><i class="bi bi-cup-hot me-1"></i> Break Type:</span>
                                                    <strong><?= $break_type ?></strong>
                                                </div>
                                            </div>
                                        </div>
                                    <?php endif; ?>

                                    <div class="alert alert-warning">
                                        <i class="bi bi-exclamation-triangle-fill me-2"></i>
                                        Are you sure you want to end this break now?
                                    </div>
                                    </div>

                                    <form method="POST" action="">
                                        <input type="hidden" name="id" value="<?= $emp['id'] ?>">
                                        <div class="d-grid gap-2">
                                            <button type="submit" name="end_break" class="btn btn-danger">
                                                <i class="bi bi-cup me-2"></i> Yes, End Break Now
                                            </button>
                                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                        </div>
                                    </form>
                                </div>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>

            <?php endif; ?>
        <?php endwhile; ?>
    <?php endif; ?>

    <!-- Attendance History Modals -->
    <?php
    if ($employees):
        $employees->data_seek(0); // Reset result pointer
        while ($emp = $employees->fetch_assoc()):
    ?>
            <!-- Attendance History Modal for each employee -->
            <div class="modal fade" id="attendanceHistoryModal<?= $emp['id'] ?>" tabindex="-1" aria-labelledby="attendanceHistoryModalLabel<?= $emp['id'] ?>" aria-hidden="true">
                <div class="modal-dialog modal-lg modal-dialog-scrollable">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title" id="attendanceHistoryModalLabel<?= $emp['id'] ?>">
                                <i class="bi bi-calendar-check me-2"></i>Attendance History: <?= htmlspecialchars($emp['name']) ?>
                            </h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body p-0">
                            <?php
                            // Get attendance history for this employee
                            $history_stmt = $conn->prepare("
                            SELECT 
                                a.id,
                                a.date,
                                a.check_in,
                                a.check_out,
                                a.break_start,
                                a.break_end,
                                TIMEDIFF(COALESCE(a.check_out, NOW()), a.check_in) AS total_hours,
                                TIMEDIFF(COALESCE(a.break_end, NOW()), a.break_start) AS break_duration,
                                CASE
                                    WHEN a.check_in IS NULL THEN 'absent'
                                    WHEN a.check_out IS NULL THEN 'working'
                                    ELSE 'complete'
                                END AS status
                            FROM 
                                attendance a
                            WHERE 
                                a.employee_id = ?
                            ORDER BY 
                                a.date DESC
                            LIMIT 30
                        ");
                            $history_stmt->bind_param("i", $emp['id']);
                            $history_stmt->execute();
                            $history_result = $history_stmt->get_result();

                            // Get break details for this employee
                            $break_stmt = $conn->prepare("
                            SELECT 
                                bs.id,
                                bs.break_start,
                                bs.scheduled_end,
                                bs.actual_end,
                                COALESCE(bs.break_type, 'lunch') AS break_type,
                                TIMESTAMPDIFF(MINUTE, bs.break_start, COALESCE(bs.actual_end, NOW())) AS duration_minutes,
                                a.date
                            FROM 
                                break_schedule bs
                                JOIN attendance a ON bs.employee_id = a.employee_id AND DATE(bs.break_start) = a.date
                            WHERE 
                                bs.employee_id = ?
                            ORDER BY 
                                bs.break_start DESC
                            LIMIT 30
                        ");
                            $break_stmt->bind_param("i", $emp['id']);
                            $break_stmt->execute();
                            $break_result = $break_stmt->get_result();

                            // Create an array to store breaks by date
                            $breaks_by_date = [];
                            while ($break = $break_result->fetch_assoc()) {
                                $date = date('Y-m-d', strtotime($break['date']));
                                if (!isset($breaks_by_date[$date])) {
                                    $breaks_by_date[$date] = [];
                                }
                                $breaks_by_date[$date][] = $break;
                            }

                            // Get statistics
                            $total_days = $history_result->num_rows;
                            $present_days = 0;
                            $absent_days = 0;
                            $complete_days = 0;
                            $total_hours = 0;
                            $days_with_breaks = 0;
                            $days_without_breaks = 0;
                            ?>

                            <?php if ($history_result->num_rows > 0): ?>
                                <!-- Summary Card -->
                                <div class="card m-3 attendance-summary-card">
                                    <div class="card-header">
                                        <i class="bi bi-graph-up me-2"></i>Attendance Summary
                                    </div>
                                    <div class="card-body">
                                        <div class="row">
                                            <?php
                                            // Calculate summary statistics
                                            $history_result_copy = $history_result;
                                            while ($row = $history_result_copy->fetch_assoc()) {
                                                if ($row['check_in']) {
                                                    $present_days++;
                                                    if ($row['check_out']) {
                                                        $complete_days++;
                                                        // Calculate total hours
                                                        $parts = explode(':', $row['total_hours']);
                                                        $hours = intval($parts[0]);
                                                        $minutes = intval($parts[0]) / 60;
                                                        $total_hours += $hours + $minutes;
                                                    }
                                                } else {
                                                    $absent_days++;
                                                }

                                                $date = date('Y-m-d', strtotime($row['date']));
                                                if (isset($breaks_by_date[$date]) && count($breaks_by_date[$date]) > 0) {
                                                    $days_with_breaks++;
                                                } else if ($row['check_in']) {
                                                    $days_without_breaks++;
                                                }
                                            }
                                            $history_result->data_seek(0); // Reset pointer
                                            ?>

                                            <div class="col-md-3 mb-3">
                                                <div class="card h-100 border-0 attendance-stat-card">
                                                    <div class="card-body text-center">
                                                        <h1 class="display-4 text-primary"><?= $present_days ?></h1>
                                                        <p class="text-muted mb-0">Days Present</p>
                                                    </div>
                                                </div>
                                            </div>

                                            <div class="col-md-3 mb-3">
                                                <div class="card h-100 border-0 attendance-stat-card">
                                                    <div class="card-body text-center">
                                                        <h1 class="display-4 text-success"><?= round($total_hours, 1) ?></h1>
                                                        <p class="text-muted mb-0">Total Hours</p>
                                                    </div>
                                                </div>
                                            </div>

                                            <div class="col-md-3 mb-3">
                                                <div class="card h-100 border-0 attendance-stat-card">
                                                    <div class="card-body text-center">
                                                        <h1 class="display-4 text-warning"><?= $days_with_breaks ?></h1>
                                                        <p class="text-muted mb-0">Days with Breaks</p>
                                                    </div>
                                                </div>
                                            </div>

                                            <div class="col-md-3 mb-3">
                                                <div class="card h-100 border-0 attendance-stat-card">
                                                    <div class="card-body text-center">
                                                        <h1 class="display-4 text-danger"><?= $days_without_breaks ?></h1>
                                                        <p class="text-muted mb-0">Days without Breaks</p>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <!-- Tabs for Attendance and Breaks -->
                                <ul class="nav nav-tabs" id="attendanceTabs<?= $emp['id'] ?>" role="tablist">
                                    <li class="nav-item" role="presentation">
                                        <button class="nav-link active" id="attendance-tab<?= $emp['id'] ?>" data-bs-toggle="tab" data-bs-target="#attendance-content<?= $emp['id'] ?>" type="button" role="tab" aria-controls="attendance-content<?= $emp['id'] ?>" aria-selected="true">
                                            <i class="bi bi-calendar-check me-1"></i> Attendance
                                        </button>
                                    </li>
                                    <li class="nav-item" role="presentation">
                                        <button class="nav-link" id="breaks-tab<?= $emp['id'] ?>" data-bs-toggle="tab" data-bs-target="#breaks-content<?= $emp['id'] ?>" type="button" role="tab" aria-controls="breaks-content<?= $emp['id'] ?>" aria-selected="false">
                                            <i class="bi bi-cup-hot me-1"></i> Breaks
                                        </button>
                                    </li>
                                </ul>

                                <div class="tab-content">
                                    <!-- Attendance Table Tab -->
                                    <div class="tab-pane fade show active" id="attendance-content<?= $emp['id'] ?>" role="tabpanel" aria-labelledby="attendance-tab<?= $emp['id'] ?>">
                                        <div class="table-responsive">
                                            <table class="table table-striped table-hover mb-0">
                                                <thead>
                                                    <tr>
                                                        <th>Date</th>
                                                        <th>Check In</th>
                                                        <th>Check Out</th>
                                                        <th>Break Status</th>
                                                        <th>Total Hours</th>
                                                        <th>Status</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    <?php while ($row = $history_result->fetch_assoc()):
                                                        $date = date('Y-m-d', strtotime($row['date']));
                                                        $has_breaks = isset($breaks_by_date[$date]) && count($breaks_by_date[$date]) > 0;
                                                    ?>
                                                        <tr>
                                                            <td><?= date('Y-m-d (D)', strtotime($row['date'])) ?></td>
                                                            <td><?= $row['check_in'] ? date('h:i:s A', strtotime($row['check_in'])) : '---' ?></td>
                                                            <td><?= $row['check_out'] ? date('h:i:s A', strtotime($row['check_out'])) : '---' ?></td>
                                                            <td>
                                                                <?php if ($has_breaks): ?>
                                                                    <span class="badge bg-success">
                                                                        <i class="bi bi-check-circle me-1"></i>
                                                                        <?= count($breaks_by_date[$date]) ?> break(s)
                                                                    </span>
                                                                <?php elseif ($row['check_in']): ?>
                                                                    <span class="badge bg-warning">
                                                                        <i class="bi bi-exclamation-triangle me-1"></i>
                                                                        No breaks
                                                                    </span>
                                                                <?php else: ?>
                                                                    <span class="badge bg-secondary">N/A</span>
                                                                <?php endif; ?>
                                                            </td>
                                                            <td>
                                                                <?php if ($row['check_in'] && $row['check_out']): ?>
                                                                    <?= $row['total_hours'] ?>
                                                                <?php elseif ($row['check_in'] && !$row['check_out']): ?>
                                                                    <span class="badge bg-primary">In progress</span>
                                                                <?php else: ?>
                                                                    <span class="badge bg-danger">Incomplete</span>
                                                                <?php endif; ?>
                                                            </td>
                                                            <td>
                                                                <?php if ($row['status'] == 'complete'): ?>
                                                                    <span class="badge bg-success">Complete</span>
                                                                <?php elseif ($row['status'] == 'working'): ?>
                                                                    <span class="badge bg-primary">Working</span>
                                                                <?php else: ?>
                                                                    <span class="badge bg-danger">Absent</span>
                                                                <?php endif; ?>
                                                            </td>
                                                        </tr>
                                                    <?php endwhile; ?>
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>

                                    <!-- Breaks Table Tab -->
                                    <div class="tab-pane fade" id="breaks-content<?= $emp['id'] ?>" role="tabpanel" aria-labelledby="breaks-tab<?= $emp['id'] ?>">
                                        <?php if ($break_result->num_rows > 0): ?>
                                            <div class="table-responsive">
                                                <table class="table table-striped table-hover mb-0">
                                                    <thead>
                                                        <tr>
                                                            <th>Date</th>
                                                            <th>Type</th>
                                                            <th>Start</th>
                                                            <th>Scheduled End</th>
                                                            <th>Actual End</th>
                                                            <th>Duration</th>
                                                            <th>Status</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        <?php
                                                        $break_result->data_seek(0); // Reset pointer
                                                        while ($break = $break_result->fetch_assoc()):
                                                        ?>
                                                            <tr>
                                                                <td><?= date('Y-m-d (D)', strtotime($break['date'])) ?></td>
                                                                <td>
                                                                    <?php if ($break['break_type'] == 'lunch'): ?>
                                                                        <span class="badge bg-primary">Lunch</span>
                                                                    <?php else: ?>
                                                                        <span class="badge bg-info">Rest</span>
                                                                    <?php endif; ?>
                                                                </td>
                                                                <td><?= date('h:i:s A', strtotime($break['break_start'])) ?></td>
                                                                <td><?= date('h:i:s A', strtotime($break['scheduled_end'])) ?></td>
                                                                <td>
                                                                    <?php if ($break['actual_end']): ?>
                                                                        <?= date('h:i:s A', strtotime($break['actual_end'])) ?>
                                                                    <?php else: ?>
                                                                        <span class="badge bg-warning">In progress</span>
                                                                    <?php endif; ?>
                                                                </td>
                                                                <td>
                                                                    <?= $break['duration_minutes'] ?> minutes
                                                                </td>
                                                                <td>
                                                                    <?php
                                                                    if (!$break['actual_end']) {
                                                                        echo '<span class="badge bg-warning">In progress</span>';
                                                                    } elseif (strtotime($break['actual_end']) > strtotime($break['scheduled_end'])) {
                                                                        echo '<span class="badge bg-danger">Returned late</span>';
                                                                    } else {
                                                                        echo '<span class="badge bg-success">On time</span>';
                                                                    }
                                                                    ?>
                                                                </td>
                                                            </tr>
                                                        <?php endwhile; ?>
                                                    </tbody>
                                                </table>
                                            </div>
                                        <?php else: ?>
                                            <div class="alert alert-warning m-3">
                                                <i class="bi bi-exclamation-triangle-fill me-2"></i>
                                                No break records found for this employee.
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            <?php else: ?>
                                <div class="alert alert-info m-3">
                                    <i class="bi bi-info-circle-fill me-2"></i>
                                    No attendance records found for this employee.
                                </div>
                            <?php endif; ?>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                        </div>
                    </div>
                </div>
            </div>
        <?php endwhile; ?>
    <?php endif; ?>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/sortablejs@1.14.0/Sortable.min.js"></script>

    <!-- Reorder Employees Modal -->
    <div class="modal fade" id="reorderEmployeesModal" tabindex="-1" aria-labelledby="reorderEmployeesModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="reorderEmployeesModalLabel"><i class="bi bi-arrow-down-up me-2"></i>Reorder Employees</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div class="alert alert-info">
                        <i class="bi bi-info-circle-fill me-2"></i>
                        Drag and drop employees to reorder them. Click "Save Order" when you're done.
                    </div>

                    <div class="input-group mb-3">
                        <span class="input-group-text"><i class="bi bi-search"></i></span>
                        <input type="text" class="form-control" id="employeeSearch" placeholder="Search employee name or email..." onkeyup="filterEmployees()">
                    </div>

                    <ul class="list-group" id="employeesList">
                        <?php
                        $employees->data_seek(0); // Reset pointer
                        while ($emp = $employees->fetch_assoc()):
                        ?>
                            <li class="list-group-item d-flex justify-content-between align-items-center" data-id="<?= $emp['id'] ?>">
                                <div class="d-flex align-items-center">
                                    <span class="order-number badge bg-primary me-3" style="width: 30px; height: 30px; border-radius: 50%; display: flex; align-items: center; justify-content: center;"></span>
                                    <div>
                                        <span class="fw-bold"><?= htmlspecialchars($emp['name']) ?></span>
                                        <small class="d-block text-muted">ID: <?= $emp['id'] ?> | <?= htmlspecialchars($emp['email']) ?></small>
                                    </div>
                                </div>
                                <span class="drag-handle"><i class="bi bi-grip-vertical"></i></span>
                            </li>
                        <?php endwhile; ?>
                    </ul>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" id="saveOrderBtn">
                        <i class="bi bi-save me-1"></i> Save Order
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Save Order Form (hidden) -->
    <form id="orderForm" method="post" action="save_employee_order.php" style="display: none;">
        <input type="hidden" id="employeeOrder" name="employeeOrder" value="">
    </form>

    <script>
        function deleteEmployee(id) {
            if (confirm('Are you sure you want to delete this employee? This action cannot be undone.')) {
                window.location.href = `admin.php?delete=${id}`;
            }
        }
        
        // Function to handle theme radio button changes
        function handleThemeChange() {
            const themeRadios = document.querySelectorAll('input[name="theme_color"]');
            const themeInput = document.getElementById('theme_color_input');
            
            // Ensure the hidden input value matches the selected radio button on load
            themeRadios.forEach(radio => {
                if (radio.checked) {
                    themeInput.value = radio.value;
                }
                
                // Add change event listener
                radio.addEventListener('change', function() {
                    if (this.checked) {
                        themeInput.value = this.value;
                        console.log('Theme changed to: ' + this.value);
                    }
                });
            });
        }

        // Add touch-friendly horizontal scrolling for tables on mobile
        document.addEventListener('DOMContentLoaded', function() {
            // Initialize theme selection handler
            handleThemeChange();
            
            // Start break timers for employees on break
            startBreakTimers();

            // Update break timers every second
            setInterval(updateBreakTimers, 1000);

            // Initialize Sortable for employee reordering
            var employeesList = document.getElementById('employeesList');
            if (employeesList) {
                // Update order numbers initially
                updateOrderNumbers();

                new Sortable(employeesList, {
                    animation: 150,
                    handle: '.drag-handle',
                    ghostClass: 'sortable-ghost',
                    chosenClass: 'sortable-chosen',
                    dragClass: 'sortable-drag',
                    onEnd: function() {
                        // Update order numbers when sorting ends
                        updateOrderNumbers();
                    }
                });

                // Function to update the order numbers
                function updateOrderNumbers() {
                    var items = employeesList.querySelectorAll('li:not([style*="display: none"])');
                    items.forEach(function(item, index) {
                        var orderNumber = item.querySelector('.order-number');
                        if (orderNumber) {
                            orderNumber.textContent = index + 1;
                        }
                    });
                }

                // Function to filter employees
                window.filterEmployees = function() {
                    var input = document.getElementById('employeeSearch');
                    var filter = input.value.toUpperCase();
                    var items = employeesList.querySelectorAll('li');

                    items.forEach(function(item) {
                        var name = item.querySelector('.fw-bold').textContent;
                        var email = item.querySelector('.text-muted').textContent;
                        var textContent = name + ' ' + email;

                        if (textContent.toUpperCase().indexOf(filter) > -1) {
                            item.style.display = "";
                        } else {
                            item.style.display = "none";
                        }
                    });

                    // Update order numbers after filtering
                    updateOrderNumbers();
                }

                // Add event listener for the Save Order button
                document.getElementById('saveOrderBtn').addEventListener('click', function() {
                    // Get the new order of employee IDs
                    var items = employeesList.querySelectorAll('li');
                    var orderData = [];

                    items.forEach(function(item, index) {
                        orderData.push({
                            id: item.getAttribute('data-id'),
                            position: index + 1
                        });
                    });

                    // Set the value to the hidden form field
                    document.getElementById('employeeOrder').value = JSON.stringify(orderData);

                    // Submit the form
                    document.getElementById('orderForm').submit();
                });
            }

            const tableResponsives = document.querySelectorAll('.table-responsive');

            // Function to handle auto-scrolling
            function autoScrollTable(tableContainer) {
                // Get current scroll position
                const currentScroll = tableContainer.scrollLeft;
                const maxScroll = tableContainer.scrollWidth - tableContainer.clientWidth;

                // If already at the end, go back to start, otherwise scroll to end
                if (currentScroll >= maxScroll - 10) {
                    // Smooth scroll to start
                    tableContainer.scrollTo({
                        left: 0,
                        behavior: 'smooth'
                    });
                } else {
                    // Smooth scroll to end
                    tableContainer.scrollTo({
                        left: maxScroll,
                        behavior: 'smooth'
                    });
                }
            }

            // Make scroll indicators clickable
            const scrollIndicators = document.querySelectorAll('.scroll-indicator');
            scrollIndicators.forEach(indicator => {
                indicator.addEventListener('click', function() {
                    // Find the associated table container
                    const tableContainer = this.nextElementSibling;
                    if (tableContainer && tableContainer.classList.contains('table-responsive')) {
                        autoScrollTable(tableContainer);
                    }
                });
            });

            // Function to initialize break timers
            function startBreakTimers() {
                // Find all break timers elements by class
                const breakTimers = document.querySelectorAll('.break-timer-element');

                breakTimers.forEach(timer => {
                    try {
                        if (!timer.dataset.startTime) return;

                        // Parse the start time with error handling
                        const startTime = new Date(timer.dataset.startTime);
                        // Skip if invalid date
                        if (isNaN(startTime.getTime())) {
                            timer.textContent = "0m 0s";
                            return;
                        }

                        const currentTime = new Date();

                        // Calculate elapsed time in seconds with validation
                        let elapsedSeconds = 0;
                        try {
                            elapsedSeconds = Math.floor((currentTime - startTime) / 1000);
                            if (isNaN(elapsedSeconds) || elapsedSeconds < 0) elapsedSeconds = 0;
                        } catch (e) {
                            console.error("Error calculating elapsed time", e);
                            elapsedSeconds = 0;
                        }

                        // Initialize timer
                        timer.dataset.elapsedSeconds = elapsedSeconds;

                        // Set initial display
                        updateTimerDisplay(timer);
                    } catch (e) {
                        console.error("Error initializing break timer", e);
                        if (timer) timer.textContent = "0m 0s";
                    }
                });
            }

            // Function to update break timers
            function updateBreakTimers() {
                const breakTimers = document.querySelectorAll('.break-timer-element');

                breakTimers.forEach(timer => {
                    try {
                        if (!timer.dataset.elapsedSeconds) {
                            timer.textContent = "0m 0s";
                            return;
                        }

                        // Increment elapsed seconds
                        let elapsedSeconds = parseInt(timer.dataset.elapsedSeconds) || 0;
                        if (isNaN(elapsedSeconds)) elapsedSeconds = 0;

                        elapsedSeconds += 1;
                        timer.dataset.elapsedSeconds = elapsedSeconds;

                        updateTimerDisplay(timer);
                    } catch (e) {
                        console.error("Error updating break timer", e);
                        if (timer) timer.textContent = "0m 0s";
                    }
                });
            }

            // Helper function to update timer display
            function updateTimerDisplay(timer) {
                try {
                    const elapsedSeconds = parseInt(timer.dataset.elapsedSeconds) || 0;

                    // Format time
                    const hours = Math.floor(elapsedSeconds / 3600);
                    const minutes = Math.floor((elapsedSeconds % 3600) / 60);
                    const seconds = elapsedSeconds % 60;

                    // Display formatted time
                    let timeDisplay = '';
                    if (hours > 0) {
                        timeDisplay = `${hours}h ${minutes}m ${seconds}s`;
                    } else {
                        timeDisplay = `${minutes}m ${seconds}s`;
                    }

                    timer.textContent = timeDisplay;

                    // Change color based on duration (optional)
                    if (elapsedSeconds > 900) { // 15 minutes
                        timer.classList.add('text-danger');
                    } else if (elapsedSeconds > 600) { // 10 minutes
                        timer.classList.add('text-warning');
                    }
                } catch (e) {
                    console.error("Error formatting timer display", e);
                    timer.textContent = "0m 0s";
                }
            }

            // Specific handling for main employee table
            const mainScrollIndicator = document.getElementById('scrollIndicator');
            const employeeTable = document.getElementById('employeeTableContainer');
            if (mainScrollIndicator && employeeTable) {
                mainScrollIndicator.addEventListener('click', function() {
                    autoScrollTable(employeeTable);
                });
            }

            tableResponsives.forEach(container => {
                // Check if scrolling is needed
                function checkForScrolling() {
                    // Show/hide scroll indicators based on actual content overflow
                    const needsScrolling = container.scrollWidth > container.clientWidth;
                    const tableContainer = container.closest('.table-container');

                    if (tableContainer) {
                        const scrollIndicator = tableContainer.querySelector('.scroll-indicator');

                        if (scrollIndicator) {
                            if (needsScrolling && window.innerWidth < 992) {
                                scrollIndicator.style.display = 'block';
                            } else {
                                scrollIndicator.style.display = 'none';
                            }
                        }

                        // Add shadow effect to indicate more content
                        if (needsScrolling) {
                            tableContainer.classList.add('has-overflow');
                        } else {
                            tableContainer.classList.remove('has-overflow');
                        }
                    }
                }

                // Initial check
                setTimeout(checkForScrolling, 100); // Slight delay to ensure DOM is fully rendered

                // Check on window resize
                window.addEventListener('resize', checkForScrolling);

                // Add touch-friendly scrolling indicators
                if (window.matchMedia('(max-width: 992px)').matches) {
                    let isScrolling;

                    // Hide indicators when user is actively scrolling
                    container.addEventListener('scroll', function() {
                        const tableContainer = container.closest('.table-container');
                        if (tableContainer) {
                            tableContainer.classList.add('is-scrolling');
                        }

                        // Clear timeout
                        clearTimeout(isScrolling);

                        // Set timeout to determine when scrolling stops
                        isScrolling = setTimeout(function() {
                            const tableContainer = container.closest('.table-container');
                            if (tableContainer) {
                                tableContainer.classList.remove('is-scrolling');
                            }
                        }, 100);
                    });
                }
            });

            // Also add scroll indicators to modal on open
            const accessAttemptsModal = document.getElementById('accessAttemptsModal');
            if (accessAttemptsModal) {
                accessAttemptsModal.addEventListener('shown.bs.modal', function() {
                    const modalScrollIndicator = accessAttemptsModal.querySelector('.scroll-indicator');
                    const modalTableContainer = accessAttemptsModal.querySelector('.table-responsive');

                    // If indicator doesn't exist, create one
                    if (!modalScrollIndicator && modalTableContainer) {
                        const needsScrolling = modalTableContainer.scrollWidth > modalTableContainer.clientWidth;

                        if (needsScrolling && window.innerWidth < 992) {
                            const newIndicator = document.createElement('div');
                            newIndicator.className = 'scroll-indicator';
                            newIndicator.innerHTML = '<i class="bi bi-arrow-left-right"></i> Swipe horizontally to view all data';

                            const tableContainer = modalTableContainer.closest('.table-container') || modalTableContainer.parentNode;
                            tableContainer.insertBefore(newIndicator, modalTableContainer);

                            // Make it clickable
                            newIndicator.addEventListener('click', function() {
                                autoScrollTable(modalTableContainer);
                            });
                        }
                    }
                });
            }
        });
    </script>

    <!-- Maintenance Mode Modal -->
    <div class="modal fade" id="maintenanceModeModal" tabindex="-1" aria-labelledby="maintenanceModeModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header" style="background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%); color: white;">
                    <h5 class="modal-title" id="maintenanceModeModalLabel"><i class="bi bi-lock-fill me-2"></i>Enable Maintenance Mode</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div class="alert alert-warning">
                        <i class="bi bi-exclamation-triangle-fill me-2"></i>
                        <strong>Warning:</strong> Enabling maintenance mode will prevent all employees from logging in.
                    </div>

                    <form method="POST" action="">
                        <div class="mb-3">
                            <label for="maintenance_reason" class="form-label">Maintenance Reason</label>
                            <textarea class="form-control" id="maintenance_reason" name="maintenance_reason" rows="3" placeholder="Enter reason for maintenance (will be displayed to employees)"><?= htmlspecialchars($maintenance_reason) ?></textarea>
                            <small class="text-muted">This message will be shown to employees when they try to log in.</small>
                        </div>

                        <div class="d-grid gap-2">
                            <button type="submit" name="enable_maintenance" class="btn btn-warning">
                                <i class="bi bi-lock-fill me-2"></i> Enable Maintenance Mode
                            </button>
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <!-- Add System Settings Modal -->
    <div class="modal fade" id="systemSettingsModal" tabindex="-1" aria-labelledby="systemSettingsModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header" style="background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%); color: white;">
                    <h5 class="modal-title" id="systemSettingsModalLabel"><i class="bi bi-gear-fill me-2"></i>System Settings</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div class="row">
                        <!-- Maintenance Mode Card -->
                        <div class="col-md-6 mb-4">
                            <div class="card h-100">
                                <div class="card-header bg-warning text-white">
                                    <i class="bi bi-shield-lock-fill me-2"></i>Maintenance Mode
                                </div>
                                <div class="card-body">
                                    <p>Enable maintenance mode to prevent employees from logging in during system updates or maintenance periods.</p>

                                    <?php if ($maintenance_mode): ?>
                                        <div class="alert alert-warning mb-3">
                                            <i class="bi bi-exclamation-triangle-fill me-2"></i>
                                            <strong>Maintenance mode is currently ENABLED</strong><br>
                                            Reason: <?= htmlspecialchars($maintenance_reason) ?>
                                        </div>

                                        <form method="POST" action="" class="d-grid">
                                            <button type="submit" name="disable_maintenance" class="btn btn-success" onclick="return confirm('Are you sure you want to turn off maintenance mode? This will allow employees to log in again.')">
                                                <i class="bi bi-unlock-fill me-1"></i> Disable Maintenance Mode
                                            </button>
                                        </form>
                                    <?php else: ?>
                                        <div class="alert alert-success mb-3">
                                            <i class="bi bi-check-circle-fill me-2"></i>
                                            <strong>Maintenance mode is currently DISABLED</strong><br>
                                            Employees can log in normally.
                                        </div>

                                        <button type="button" class="btn btn-warning w-100" data-bs-toggle="modal" data-bs-target="#maintenanceModeModal">
                                            <i class="bi bi-lock-fill me-1"></i> Enable Maintenance Mode
                                        </button>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>

                        <!-- Employee Order Card -->
                        <div class="col-md-6 mb-4">
                            <div class="card h-100">
                                <div class="card-header bg-primary text-white">
                                    <i class="bi bi-arrow-down-up me-2"></i>Employee Settings
                                </div>
                                <div class="card-body">
                                    <p>Change the order in which employees are displayed in the employee list and dashboards.</p>

                                    <div class="d-grid">
                                        <button type="button" class="btn btn-primary w-100" data-bs-toggle="modal" data-bs-target="#reorderEmployeesModal">
                                            <i class="bi bi-arrow-down-up me-1"></i> Reorder Employees
                                        </button>
                                        <p class="mt-3">Logout All Employees Make Sure You Know What You Are Doing</p>
                                        <form method="POST" action="" class="d-inline">
                                            <button type="submit" name="logout_all_employees" class="btn btn-danger w-100" onclick="return confirm('Are you sure you want to log out ALL employees? This will end their current shifts.')">
                                                <i class="bi bi-people-fill me-1"></i> Logout All Employees
                                            </button>
                                        </form>
                                       
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- System Backup Card -->
                        <div class="col-md-6 mb-4">
                            <div class="card h-100">
                                <div class="card-header bg-info text-white">
                                    <i class="bi bi-download me-2"></i>System Backup
                                </div>
                                <div class="card-body">
                                    <p>Create a backup of your system data for disaster recovery.</p>

                                    <div class="d-grid">
                                        <a href="system_backup.php" class="btn btn-info text-white w-100">
                                            <i class="bi bi-download me-1"></i> Backup System Data
                                        </a>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- Security Settings Card -->
                        <div class="col-md-6 mb-4">
                            <div class="card h-100">
                                <div class="card-header bg-danger text-white">
                                    <i class="bi bi-shield-lock me-2"></i>Security Settings
                                </div>
                                <div class="card-body">
                                    <p>Manage security settings and access logs for your system.</p>

                                    <div class="d-grid gap-2">
                                        <button type="button" class="btn btn-warning w-100" data-bs-toggle="modal" data-bs-target="#accessAttemptsModal">
                                            <i class="bi bi-shield-exclamation me-1"></i> View Access Logs
                                        </button>
                                        <a href="admin_reset.php?token=debug_token_12345678" class="btn btn-danger">
                                            <button type="button" class="btn btn-danger w-100">
                                                <i class="bi bi-shield-lock me-1"></i> Change Admin Password
                                            </button>
                                        </a>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Theme Settings Card -->
                        <div class="col-md-6 mb-4">
                            <div class="card h-100">
                                <div class="card-header bg-success text-white">
                                    <i class="bi bi-palette-fill me-2"></i>Theme Settings
                                </div>
                                <div class="card-body">
                                    <p>Change the color theme for the entire application.</p>
                                    
                                    <!-- Theme color is already loaded via getAdminThemeColor() -->
                                    
                                    <div class="d-flex gap-3 mb-3">
                                        <div class="form-check form-check-inline">
                                            <input class="form-check-input" type="radio" name="theme_color" id="theme_purple" value="purple" <?= $theme_color === 'purple' ? 'checked' : '' ?>>
                                            <label class="form-check-label" for="theme_purple">
                                                <span class="badge" style="background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%); width: 80px; height: 30px;"></span>
                                                Purple/Blue Theme
                                            </label>
                                        </div>
                                        <div class="form-check">
                                            <input class="form-check-input" type="radio" name="theme_color" id="theme_red" value="red" <?= $theme_color === 'red' ? 'checked' : '' ?>>
                                            <label class="form-check-label" for="theme_red">
                                                <span class="badge" style="background: linear-gradient(135deg, #cb1111 0%, #fc2525 100%); width: 80px; height: 30px;"></span>
                                                Red Theme
                                            </label>
                                        </div>
                                    </div>

                                    <form method="POST" action="">
                                        <input type="hidden" id="theme_color_input" name="theme_color_input" value="<?= $theme_color ?>">
                                        <div class="d-grid">
                                            <button type="submit" name="update_theme" class="btn btn-success w-100">
                                                <i class="bi bi-check-circle me-1"></i> Apply Theme
                                            </button>
                                        </div>
                                    </form>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Theme Changed Modal -->
    <div class="modal fade" id="themeChangedModal" tabindex="-1" aria-labelledby="themeChangedModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header bg-success text-white">
                    <h5 class="modal-title" id="themeChangedModalLabel"><i class="bi bi-palette-fill me-2"></i>Theme Updated</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <p class="mb-0">Your theme has been updated successfully!</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-primary" data-bs-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Add script to show theme changed modal if success message exists -->
    <?php if (isset($_SESSION['success_message']) && strpos($_SESSION['success_message'], 'theme updated') !== false): ?>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const themeChangedModal = new bootstrap.Modal(document.getElementById('themeChangedModal'));
            themeChangedModal.show();
            
            // Clear success message after showing modal to prevent it from showing again on refresh
            <?php unset($_SESSION['success_message']); ?>
            
            // Prevent form resubmission when page is refreshed
            if (window.history.replaceState) {
                window.history.replaceState(null, null, window.location.href);
            }
        });
    </script>
    <?php endif; ?>

    <!-- Global script to prevent form resubmission on refresh -->
    <script>
        // Run this for all pages after POST to prevent resubmission on refresh
        if (window.history.replaceState && '<?= $_SERVER['REQUEST_METHOD'] ?>' === 'POST') {
            window.history.replaceState(null, null, window.location.href);
        }
    </script>

    <!-- License Countdown Script -->
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const countdownElements = document.querySelectorAll('.license-countdown');
            
            countdownElements.forEach(function(element) {
                const endDate = new Date(element.getAttribute('data-end'));
                const daysEl = element.querySelector('.days');
                const hoursEl = element.querySelector('.hours');
                const minutesEl = element.querySelector('.minutes');
                
                function updateCountdown() {
                    const now = new Date();
                    const diff = endDate - now;
                    
                    if (diff <= 0) {
                        // License expired
                        daysEl.textContent = '00';
                        hoursEl.textContent = '00';
                        minutesEl.textContent = '00';
                        return;
                    }
                    
                    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
                    const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
                    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
                    
                    daysEl.textContent = days < 10 ? '0' + days : days;
                    hoursEl.textContent = hours < 10 ? '0' + hours : hours;
                    minutesEl.textContent = minutes < 10 ? '0' + minutes : minutes;
                }
                
                // Update immediately and then every minute
                updateCountdown();
                setInterval(updateCountdown, 60000);
            });
            
            // Format date and time in Arabic
            function updateArabicDateTime() {
                const now = new Date();
                const options = { 
                    weekday: 'long', 
                    year: 'numeric', 
                    month: 'long', 
                    day: 'numeric' 
                };
                
                const dateEl = document.getElementById('currentDateEnglish');
                const timeEl = document.getElementById('currentTimeEnglish');
                
                if (dateEl) {
                    dateEl.textContent = new Intl.DateTimeFormat('en-US', options).format(now);
                }
                
                if (timeEl) {
                    const hours = now.getHours().toString().padStart(2, '0');
                    const minutes = now.getMinutes().toString().padStart(2, '0');
                    const seconds = now.getSeconds().toString().padStart(2, '0');
                    timeEl.textContent = `${hours}:${minutes}:${seconds}`;
                }
            }
            
            // Update date/time immediately and then every second
            updateArabicDateTime();
            setInterval(updateArabicDateTime, 1000);
            
            // Load attendance chart when modal is opened
            const systemStatsModal = document.getElementById('systemStatsModal');
            if (systemStatsModal) {
                systemStatsModal.addEventListener('shown.bs.modal', function () {
                    // Load Chart.js if needed
                    if (typeof Chart === 'undefined') {
                        const script = document.createElement('script');
                        script.src = 'https://cdn.jsdelivr.net/npm/chart.js';
                        script.onload = initAttendanceChart;
                        document.head.appendChild(script);
                    } else {
                        initAttendanceChart();
                    }
                });
            }
            
            function initAttendanceChart() {
                const ctx = document.getElementById('attendanceChart');
                
                if (!ctx) return;
                
                // Sample data - in a real application, this would come from the server
                const attendanceData = {
                    labels: ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'],
                    datasets: [{
                        label: 'Attendance Count',
                        data: [12, 15, 13, 14, 10, 8, 5],
                        backgroundColor: 'rgba(54, 162, 235, 0.2)',
                        borderColor: 'rgba(54, 162, 235, 1)',
                        borderWidth: 1
                    }]
                };
                
                new Chart(ctx, {
                    type: 'bar',
                    data: attendanceData,
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        }
                    }
                });
            }
        });
    </script>

    <!-- System Statistics Modal -->
    <div class="modal fade" id="systemStatsModal" tabindex="-1" aria-labelledby="systemStatsModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header bg-primary text-white">
                    <h5 class="modal-title" id="systemStatsModalLabel"><i class="bi bi-bar-chart-fill me-2"></i>System Statistics</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <!-- Current Date & Time -->
                    <div class="alert alert-info mb-4">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <strong><i class="bi bi-calendar-date me-2"></i>Current Date:</strong>
                            <span id="currentDateEnglish"></span>
                        </div>
                        <div class="d-flex justify-content-between align-items-center">
                            <strong><i class="bi bi-clock me-2"></i>Current Time:</strong>
                            <span id="currentTimeEnglish"></span>
                        </div>
                    </div>

                    <div class="row">
                        <!-- System Stats -->
                        <div class="col-md-6 mb-4">
                            <div class="card border-0 shadow-sm h-100">
                                <div class="card-header bg-info bg-opacity-25 border-0">
                                    <h5 class="mb-0"><i class="bi bi-lightning-charge me-2"></i>General Statistics</h5>
                                </div>
                                <div class="card-body">
                                    <ul class="list-group list-group-flush">
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            Total Employees
                                            <span class="badge rounded-pill bg-success"><?= $employeesCount ?></span>
                                        </li>
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            Active Employees Today
                                            <span class="badge rounded-pill bg-primary"><?= $checkedInCount ?></span>
                                        </li>
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            Total Attendance Records
                                            <?php
                                            $total_attendance = $conn->query("SELECT COUNT(*) as count FROM attendance")->fetch_assoc()['count'];
                                            ?>
                                            <span class="badge rounded-pill bg-info"><?= $total_attendance ?></span>
                                        </li>
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            Breaks Today
                                            <?php
                                            $today_breaks = $conn->query("SELECT COUNT(*) as count FROM break_schedule WHERE DATE(break_start) = CURRENT_DATE")->fetch_assoc()['count'];
                                            ?>
                                            <span class="badge rounded-pill bg-warning"><?= $today_breaks ?></span>
                                        </li>
                                    </ul>
                                </div>
                            </div>
                        </div>

                        <!-- License Stats -->
                        <div class="col-md-6 mb-4">
                            <div class="card border-0 shadow-sm h-100">
                                <div class="card-header bg-success bg-opacity-25 border-0">
                                    <h5 class="mb-0"><i class="bi bi-shield-check me-2"></i>License Information</h5>
                                </div>
                                <div class="card-body">
                                    <ul class="list-group list-group-flush">
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            License Status
                                            <span class="badge rounded-pill bg-success">Active</span>
                                        </li>
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            License Type
                                            <span class="badge rounded-pill bg-primary">Admin Dashboard</span>
                                        </li>
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            Expiration Date
                                            <span class="badge rounded-pill bg-<?= $status ?>"><?= date('d-m-Y', strtotime($license_result['end_date'])) ?></span>
                                        </li>
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            Days Remaining
                                            <span class="badge rounded-pill bg-<?= $status ?>"><?= $daysLeft ?> days</span>
                                        </li>
                                    </ul>
                                </div>
                            </div>
                        </div>

                        <!-- Attendance Chart -->
                        <div class="col-md-12">
                            <div class="card border-0 shadow-sm">
                                <div class="card-header bg-primary bg-opacity-25 border-0">
                                    <h5 class="mb-0"><i class="bi bi-graph-up me-2"></i>Current Week Attendance Statistics</h5>
                                </div>
                                <div class="card-body">
                                    <div class="chart-container" style="position: relative; height:250px;">
                                        <canvas id="attendanceChart"></canvas>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <a href="attendance_reports.php" class="btn btn-info">
                        <i class="bi bi-file-earmark-text me-1"></i>Detailed Reports
                    </a>
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Employee Location Settings Modal -->
    <div class="modal fade" id="employeeLocationSettingsModal" tabindex="-1" aria-labelledby="employeeLocationSettingsModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header bg-primary text-white">
                    <h5 class="modal-title" id="employeeLocationSettingsModalLabel"><i class="bi bi-geo-alt-fill me-2"></i>Manage Employee Locations</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div class="alert alert-info">
                        <i class="bi bi-info-circle-fill me-2"></i>
                        Select an employee from the list below to set their allowed check-in location and range.
                    </div>

                    <div class="mb-3">
                        <label for="employeeSelect" class="form-label">Select Employee</label>
                        <select class="form-select" id="employee_id_modal" name="employee_id" required>
                                <option value="">Select Employee</option>
                                <?php 
                                $employees->data_seek(0); // Reset pointer
                                if ($employees): while ($emp = $employees->fetch_assoc()): 
                                ?>
                                    <option value="<?= $emp['id'] ?>" <?= $selected_employee_id == $emp['id'] ? 'selected' : '' ?>>
                                        <?= htmlspecialchars($emp['name']) ?>
                                    </option>
                                <?php endwhile; endif; ?>
                            </select>
                    </div>

                    <ul class="list-group" id="employeeLocationList">
                        <!-- Employee list will be loaded here via JavaScript -->
                    </ul>

                    <div id="locationSettingsFormContainer" style="display: none;">
                        <hr class="my-4">
                        <h5><span id="selectedEmployeeName"></span>'s Allowed Location</h5>
                        <form id="saveLocationForm">
                            <input type="hidden" id="selectedEmployeeId" name="employee_id">
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <label for="allowed_latitude" class="form-label">Latitude</label>
                                    <input type="number" step="any" class="form-control" id="allowed_latitude_modal" name="allowed_latitude" placeholder="e.g., 34.0522">
                                </div>
                                <div class="col-md-6 mb-3">
                                    <label for="allowed_longitude" class="form-label">Longitude</label>
                                    <input type="number" step="any" class="form-control" id="allowed_longitude_modal" name="allowed_longitude" placeholder="e.g., -118.2437">
                                </div>
                            </div>

                            <div class="mb-3">
                                <label for="allowed_range_meters" class="form-label">Allowed Range (Meters)</label>
                                <input type="number" step="1" class="form-control" id="allowed_range_meters_modal" name="allowed_range_meters" placeholder="e.g., 100">
                            </div>

                            <div class="d-grid gap-2 mt-4">
                                <button type="submit" class="btn btn-primary">
                                    <i class="bi bi-save me-1"></i> Save Location Settings
                                </button>
                            </div>
                        </form>
                    </div>

                    <div class="mt-4 pt-4 border-top">
                        <h5><i class="bi bi-globe me-2"></i>Set Default Location for All Employees</h5>
                        <p class="text-muted">Use this to set a default allowed location and range for all employees who do not currently have specific settings configured.</p>
                        <form id="setDefaultLocationForm">
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <label for="default_latitude" class="form-label">Default Latitude</label>
                                    <input type="number" step="any" class="form-control" id="default_latitude" name="default_latitude" placeholder="e.g., 34.0522">
                                </div>
                                <div class="col-md-6 mb-3">
                                    <label for="default_longitude" class="form-label">Default Longitude</label>
                                    <input type="number" step="any" class="form-control" id="default_longitude" name="default_longitude" placeholder="e.g., -118.2437">
                                </div>
                            </div>

                            <div class="mb-3">
                                <label for="default_range_meters" class="form-label">Default Allowed Range (Meters)</label>
                                <input type="number" step="1" class="form-control" id="default_range_meters" name="default_range_meters" placeholder="e.g., 100">
                            </div>

                            <div class="d-grid">
                                <button type="submit" class="btn btn-info">
                                    <i class="bi bi-globe me-1"></i> Apply Default to All
                                </button>
                            </div>
                        </form>
                    </div>

                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Global script to prevent form resubmission on refresh -->
    <script>
        // Run this for all pages after POST to prevent resubmission on refresh
        if (window.history.replaceState && '<?= $_SERVER['REQUEST_METHOD'] ?>' === 'POST') {
            window.history.replaceState(null, null, window.location.href);
        }

        // Load attendance chart when modal is opened
        const systemStatsModal = document.getElementById('systemStatsModal');
        if (systemStatsModal) {
            systemStatsModal.addEventListener('shown.bs.modal', function () {
                // Load Chart.js if needed
                if (typeof Chart === 'undefined') {
                    const script = document.createElement('script');
                    script.src = 'https://cdn.jsdelivr.net/npm/chart.js';
                    script.onload = initAttendanceChart;
                    document.head.appendChild(script);
                } else {
                    initAttendanceChart();
                }
            });
        }

        // ... existing code ...

        // Employee Location Settings Modal Logic
        const employeeLocationSettingsModal = document.getElementById('employeeLocationSettingsModal');
        const employeeLocationList = document.getElementById('employeeLocationList');
        const locationSettingsFormContainer = document.getElementById('locationSettingsFormContainer');
        const selectedEmployeeNameSpan = document.getElementById('selectedEmployeeName');
        const selectedEmployeeIdInput = document.getElementById('selectedEmployeeId');
        const allowedLatitudeModalInput = document.getElementById('allowed_latitude_modal');
        const allowedLongitudeModalInput = document.getElementById('allowed_longitude_modal');
        const allowedRangeMetersModalInput = document.getElementById('allowed_range_meters_modal');
        const employeeLocationSearchInput = document.getElementById('employeeLocationSearch');

        let allEmployees = []; // To store fetched employee data

        if (employeeLocationSettingsModal) {
            employeeLocationSettingsModal.addEventListener('shown.bs.modal', function () {
                // Fetch employees when modal is shown
                fetchEmployeesForLocationSettings();
            });

            // Event listener for employee search input
            if (employeeLocationSearchInput) {
                employeeLocationSearchInput.addEventListener('keyup', function() {
                    filterEmployeeLocationList(this.value);
                });
            }

             // Add event listener for the back button (or similar functionality) to hide form and show list
             // You'll need to add a back button/link in the form container HTML
             // For now, we'll assume a mechanism to go back.

        }

        function fetchEmployeesForLocationSettings() {
            fetch('admin.php?get_employees=true')
                .then(response => response.json())
                .then(data => {
                    allEmployees = data; // Store fetched data
                    displayEmployeeLocationList(allEmployees);
                })
                .catch(error => {
                    console.error('Error fetching employees:', error);
                    employeeLocationList.innerHTML = '<li class="list-group-item text-danger">Error loading employees.</li>';
                });
        }

        function displayEmployeeLocationList(employeesToShow) {
            if (!employeeLocationList) return; // Check if element exists
            employeeLocationList.innerHTML = ''; // Clear current list
            if (employeesToShow.length === 0) {
                employeeLocationList.innerHTML = '<li class="list-group-item">No employees found.</li>';
                return;
            }

            employeesToShow.forEach(employee => {
                const listItem = document.createElement('li');
                listItem.classList.add('list-group-item', 'list-group-item-action', 'd-flex', 'justify-content-between', 'align-items-center');
                listItem.setAttribute('data-id', employee.id);
                listItem.innerHTML = `
                    <div>
                        <span class="fw-bold">${htmlspecialchars(employee.name)}</span>
                        <small class="d-block text-muted">ID: ${employee.id} | ${htmlspecialchars(employee.email)}</small>
                    </div>
                    <i class="bi bi-chevron-right"></i>
                `;
                listItem.addEventListener('click', () => selectEmployeeForLocation(employee));
                employeeLocationList.appendChild(listItem);
            });
        }

        function selectEmployeeForLocation(employee) {
            if (!locationSettingsFormContainer || !selectedEmployeeNameSpan || !selectedEmployeeIdInput || !allowedLatitudeModalInput || !allowedLongitudeModalInput || !allowedRangeMetersModalInput) return; // Check if elements exist

            // Populate form fields
            selectedEmployeeNameSpan.textContent = htmlspecialchars(employee.name);
            selectedEmployeeIdInput.value = employee.id;
            allowedLatitudeModalInput.value = employee.allowed_latitude ?? '';
            allowedLongitudeModalInput.value = employee.allowed_longitude ?? '';
            allowedRangeMetersModalInput.value = employee.allowed_range_meters ?? '';

            // Hide list and show form
            if (employeeLocationList) employeeLocationList.style.display = 'none';
            locationSettingsFormContainer.style.display = 'block';
            const backButton = document.getElementById('backToEmployeeListBtn');
            if (backButton) backButton.style.display = 'block';
+               
+               // Hide the default location section when viewing/editing an individual employee
+               const defaultLocationSection = document.querySelector('.border-top.mt-4.pt-4');
+               if (defaultLocationSection) defaultLocationSection.style.display = 'none';
        }

        function filterEmployeeLocationList(searchTerm) {
            console.log('Filtering with term:', searchTerm);
            const lowerCaseSearchTerm = searchTerm.toLowerCase();
            const filteredEmployees = allEmployees.filter(employee => {
                // Ensure employee properties exist before calling toLowerCase
                const name = employee.name ? employee.name.toLowerCase() : '';
                const email = employee.email ? employee.email.toLowerCase() : '';
                return name.includes(lowerCaseSearchTerm) ||
                       email.includes(lowerCaseSearchTerm);
            });
            console.log('Filtered employees:', filteredEmployees);
            displayEmployeeLocationList(filteredEmployees);
        }

        // Helper function for HTML escaping (basic)
        function htmlspecialchars(str) {
            if (typeof str !== 'string') return str; // Return non-strings directly
            return str.replace(/&/g, '&amp;')
                      .replace(/</g, '&lt;')
                      .replace(/>/g, '&gt;')
                      .replace(/"/g, '&quot;')
                      .replace(/'/g, '&#039;');
        }

        });

        // Handle saving location settings via AJAX
        const saveLocationForm = document.getElementById('saveLocationForm');
        if (saveLocationForm) {
            saveLocationForm.addEventListener('submit', function(event) {
                event.preventDefault(); // Prevent default form submission

                const formData = new FormData(saveLocationForm);
                const employeeId = formData.get('employee_id');

                console.log('Attempting to save location for employee ID:', employeeId);
                console.log('Form data:');
                for (let pair of formData.entries()) {
                    console.log(pair[0] + ', ' + pair[1]); 
                }

                fetch('save_employee_location.php', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Show success message (you might want a dedicated alert area)
                        alert(data.message);
                        // Optionally refresh the employee list or update the specific item
                        fetchEmployeesForLocationSettings(); // Refresh the whole list
                        // Hide the form and show the list again
                        if (employeeLocationList) employeeLocationList.style.display = 'block';
                        if (locationSettingsFormContainer) locationSettingsFormContainer.style.display = 'none';
                        // Clear form fields
                        saveLocationForm.reset();
                        // Hide back button and show default location section
                        const backButton = document.getElementById('backToEmployeeListBtn');
                        if (backButton) backButton.style.display = 'none';
                        const defaultLocationSection = document.querySelector('.border-top.mt-4.pt-4');
                        if (defaultLocationSection) defaultLocationSection.style.display = 'block';
                    } else {
                        // Show error message
                        alert('Error: ' + data.message);
                    }
                })
                .catch(error => {
                    console.error('Error saving location settings:', error);
                    alert('An error occurred while saving location settings.');
                });
            });
        }

        // Handle setting default location via AJAX
        const setDefaultLocationForm = document.getElementById('setDefaultLocationForm');
        if (setDefaultLocationForm) {
            setDefaultLocationForm.addEventListener('submit', function(event) {
                event.preventDefault(); // Prevent default form submission

                if (confirm('Are you sure you want to set this as the default location for ALL employees who do not have a specific location set?')) {
                    const formData = new FormData(setDefaultLocationForm);
                    formData.append('set_default', 'true'); // Add flag for default setting

                    fetch('save_employee_location.php', {
                        method: 'POST',
                        body: formData
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            alert(data.message);
                            // Optionally refresh the employee list in the other modal if it's open
                            fetchEmployeesForLocationSettings();
                            // Clear form fields
                            setDefaultLocationForm.reset();
                        } else {
                            alert('Error: ' + data.message);
                        }
                    })
                    .catch(error => {
                        console.error('Error setting default location:', error);
                        alert('An error occurred while setting the default location.');
                    });
                }
            });
        }

        });

        // ... existing code ...
    </script>

    <!-- System Statistics Modal -->
</body>

</html>