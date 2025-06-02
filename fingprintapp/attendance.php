<?php
session_start();
require 'db.php';
require 'theme_helper.php';
require 'license_verifier.php';

// Verify license
$verifier = new LicenseVerifier('attendance');
$license_result = $verifier->verifyLicense();

if (!$license_result['valid']) {
    // Redirect to license activation page
    header("Location: activate_license.php?type=attendance");
    exit;
}

// Get theme color from cookie or database
$theme_color = getThemeColor($conn);

// Handle theme change request
if (isset($_POST['change_theme']) && isset($_POST['theme'])) {
    $new_theme = $_POST['theme'];
    if (in_array($new_theme, ['purple', 'red'])) {
        setThemeColor($new_theme, $conn);
        $theme_color = $new_theme;

        // Add success message
        $_SESSION['success_message'] = "Theme changed to " . ucfirst($new_theme);

        // Redirect to the same page (POST/Redirect/GET pattern)
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    }
}

// Ensure database connection is active
$conn = ensureConnection($conn);
if (!$conn) {
    session_unset();
    session_destroy();
    header("Location: login.php?error=db_connection");
    exit;
}

// Check if user is logged in
if (!isset($_SESSION['employee_id']) || !isset($_SESSION['session_id'])) {
    error_log("Session check failed: employee_id or session_id not set in session");
    session_unset();
    session_destroy();
    header("Location: login.php?error=no_session");
    exit;
}

$employee_id = $_SESSION['employee_id'];
$session_id = $_SESSION['session_id'];

// Debug log current session data
error_log("Attendance.php - Employee ID: " . $employee_id . ", Session ID: " . $session_id);

// Simplified session validation
$stmt = $conn->prepare("
    SELECT id, device_info FROM session_id 
    WHERE user_id = ? 
    AND session_id = ?
");

if (!$stmt) {
    error_log("Statement preparation failed: " . $conn->error);
    session_unset();
    session_destroy();
    header("Location: login.php?error=db_error");
    exit;
}

$stmt->bind_param("is", $employee_id, $session_id);
$stmt->execute();
$result = $stmt->get_result();
$valid_session = $result->num_rows > 0;

// Log session validation result for debugging
error_log("Session validation result: " . ($valid_session ? "Valid" : "Invalid"));

if (!$valid_session) {
    // Log detailed information
    error_log("Invalid session for Employee ID: $employee_id with Session ID: $session_id");

    // Session not valid, redirect to login
    session_unset();
    session_destroy();
    header("Location: login.php?error=invalid_session");
    exit;
}

// Retrieved session_id row
$session_row = $result->fetch_assoc();
error_log("Valid session found with row ID: " . $session_row['id']);

// Check device match
$current_device = $_SERVER['HTTP_USER_AGENT'];
if (isset($session_row['device_info']) && $session_row['device_info'] != $current_device) {
    // Different device detected - potential security issue
    error_log("Device mismatch detected for Employee ID: $employee_id. Session: {$session_row['id']}");
    error_log("Stored device: {$session_row['device_info']} | Current device: $current_device");

    // Create security alert
    $alert_msg = "Possible session hijacking attempt. Device mismatch detected.";
    $security_alert_stmt = $conn->prepare("INSERT INTO security_alerts (employee_id, alert_message, severity, device_info) VALUES (?, ?, 'high', ?)");
    if ($security_alert_stmt) {
        $security_alert_stmt->bind_param("iss", $employee_id, $alert_msg, $current_device);
        $security_alert_stmt->execute();
    }

    // Invalidate all sessions for this user
    $clear_stmt = $conn->prepare("DELETE FROM session_id WHERE user_id = ?");
    if ($clear_stmt) {
        $clear_stmt->bind_param("i", $employee_id);
        $clear_stmt->execute();
    }

    // Generate a new random password
    $new_password = bin2hex(random_bytes(4));
    $update_pwd_stmt = $conn->prepare("UPDATE employees SET password = ? WHERE id = ?");
    if ($update_pwd_stmt) {
        $update_pwd_stmt->bind_param("si", $new_password, $employee_id);
        $update_pwd_stmt->execute();
    }

    // Log them out
    session_unset();
    session_destroy();
    header("Location: login.php?error=security_violation&msg=" . urlencode("Your account has been accessed from a different device. For security, your password has been reset to: $new_password"));
    exit;
}

// Update session last activity
$update_stmt = $conn->prepare("
    UPDATE session_id 
    SET last_activity = NOW() 
    WHERE id = ?
");

if (!$update_stmt) {
    error_log("Update statement preparation failed: " . $conn->error);
} else {
    $update_stmt->bind_param("i", $session_row['id']);
    $update_stmt->execute();
}

$today = date('Y-m-d');

// Get employee info
$stmt = $conn->prepare("SELECT * FROM employees WHERE id = ?");
$stmt->bind_param("i", $employee_id);
$stmt->execute();
$result = $stmt->get_result();
$employee = $result->fetch_assoc();

if (!$employee) {
    session_destroy();
    header("Location: login.php");
    exit;
}

// Check last check-out time
$last_attendance_stmt = $conn->prepare("SELECT check_out FROM attendance WHERE employee_id = ? AND check_out IS NOT NULL ORDER BY check_out DESC LIMIT 1");
$last_attendance_stmt->bind_param("i", $employee_id);
$last_attendance_stmt->execute();
$last_attendance_result = $last_attendance_stmt->get_result();
$last_attendance = $last_attendance_result->fetch_assoc();

// Get today's attendance and break schedule
$attendance_stmt = $conn->prepare("SELECT * FROM attendance WHERE employee_id = ? AND date = ?");
$attendance_stmt->bind_param("is", $employee_id, $today);
$attendance_stmt->execute();
$attendance_result = $attendance_stmt->get_result();
$attendance = $attendance_result->fetch_assoc();

// Get current break schedule if exists
$break_schedule = null;
if ($attendance && $attendance['break_start'] && !$attendance['break_end']) {
    $break_stmt = $conn->prepare("SELECT * FROM break_schedule WHERE employee_id = ? AND actual_end IS NULL ORDER BY id DESC LIMIT 1");
    $break_stmt->bind_param("i", $employee_id);
    $break_stmt->execute();
    $break_schedule = $break_stmt->get_result()->fetch_assoc();
}

// Get recent tasks for this employee (limit to 5)
$tasks_query = $conn->prepare("
    SELECT 
        et.*
    FROM 
        employee_tasks et
    WHERE 
        et.employee_id = ?
    ORDER BY 
        CASE 
            WHEN et.status = 'pending' THEN 1
            WHEN et.status = 'in_progress' THEN 2
            WHEN et.status = 'completed' THEN 3
        END,
        CASE 
            WHEN et.priority = 'high' THEN 1
            WHEN et.priority = 'medium' THEN 2
            WHEN et.priority = 'low' THEN 3
        END,
        et.due_date ASC
    LIMIT 5
");
$tasks_query->bind_param("i", $employee_id);
$tasks_query->execute();
$tasks_result = $tasks_query->get_result();

// Get task statistics
$stats_query = $conn->prepare("
    SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
        SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
        SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END) as in_progress,
        SUM(CASE WHEN status = 'pending' AND due_date < CURDATE() THEN 1 ELSE 0 END) as overdue
    FROM employee_tasks
    WHERE employee_id = ?
");
$stats_query->bind_param("i", $employee_id);
$stats_query->execute();
$task_stats = $stats_query->get_result()->fetch_assoc();

// Calculate break duration
function calculateBreakDuration($break_start, $break_end)
{
    $start = new DateTime($break_start);
    $end = new DateTime($break_end);
    $diff = $start->diff($end);

    $minutes = $diff->i + ($diff->h * 60);

    if ($minutes < 60) {
        return $minutes . ' min';
    } else {
        $hours = floor($minutes / 60);
        $remaining_minutes = $minutes % 60;
        return $hours . 'h ' . $remaining_minutes . 'm';
    }
}

// Handle check in
if (isset($_POST['check_in'])) {
    if (!$attendance) {
        // Get employee's allowed location and range
        $allowed_latitude = $employee['allowed_latitude'];
        $allowed_longitude = $employee['allowed_longitude'];
        $allowed_range_meters = $employee['allowed_range_meters'];

        // Get current location from the request (assuming they are sent via POST)
        $current_latitude = $_POST['current_latitude'] ?? null;
        $current_longitude = $_POST['current_longitude'] ?? null;

        $location_check_passed = true;
        $location_error_message = '';

        // Perform location check if allowed location is set
        if ($allowed_latitude !== null && $allowed_longitude !== null) {
            if ($current_latitude === null || $current_longitude === null) {
                $location_check_passed = false;
                $location_error_message = "Current location not provided.";
            } else {
                // Calculate distance using the existing function
                $distance = calculateDistance($allowed_latitude, $allowed_longitude, $current_latitude, $current_longitude);

                // Default range to 0 if not set
                $effective_range = $allowed_range_meters ?? 0;

                if ($distance > $effective_range) {
                    $location_check_passed = false;
                    $location_error_message = "You are too far from the allowed check-in location (Distance: " . round($distance, 2) . " meters).";
                }
            }
        }

        if ($location_check_passed) {
        // Check if 6 hours have passed since last check-out
        $can_check_in = true;
        $hours_remaining = 0;

        if ($last_attendance && $last_attendance['check_out']) {
            $last_checkout = new DateTime($last_attendance['check_out']);
            $now = new DateTime();
            $hours_diff = $last_checkout->diff($now);
            $total_hours = $hours_diff->h + ($hours_diff->days * 24);

            if ($total_hours < 8) {
                $can_check_in = false;
                $next_checkin = clone $last_checkout;
                $next_checkin->modify('+8 hours');
                $hours_remaining = ceil(6 - $total_hours);
            }
        }

        // Check if employee is within allowed location
        if ($can_check_in) {
            // Check location if coordinates are provided
            if (isset($_POST['latitude']) && isset($_POST['longitude'])) {
                $user_lat = floatval($_POST['latitude']);
                $user_lng = floatval($_POST['longitude']);

                // Company office coordinates (replace with actual coordinates)
                $office_lat = 30.105608; // REPLACE THIS: Example latitude
                $office_lng = 31.286407; // REPLACE THIS: Example longitude
                $allowed_radius = 0.1; // Radius in kilometers

                // Calculate distance between user and office
                $distance = calculateDistance($user_lat, $user_lng, $office_lat, $office_lng);

                // If user is outside allowed radius, prevent check-in
                if ($distance > $allowed_radius) {
                    $_SESSION['error_message'] = "You must be at the office to check in. You are approximately " .
                        round($distance, 3) . " km away from the office.";
                    header("Location: " . $_SERVER['PHP_SELF']);
                    exit;
                }
            } else {
                $_SESSION['error_message'] = "Unable to verify your location. Please enable location services and try again.";
                header("Location: " . $_SERVER['PHP_SELF']);
                exit;
            }

            try {
                $conn->begin_transaction();

                // Insert attendance record directly
                $stmt = $conn->prepare("INSERT INTO attendance (employee_id, date, check_in) VALUES (?, ?, NOW())");
                $stmt->bind_param("is", $employee_id, $today);

                if ($stmt->execute()) {
                    $conn->commit();
                    $_SESSION['success_message'] = "Check-in successful";
                } else {
                    throw new Exception("Check-in failed");
                }
            } catch (Exception $e) {
                $conn->rollback();
                error_log("Check-in error: " . $e->getMessage());
                $_SESSION['error_message'] = "Check-in error: " . $e->getMessage();
            }
        } else {
            $_SESSION['error_message'] = "Wait " . $hours_remaining . " more hours before checking in again. You can check in at " . $next_checkin->format('h:i A');
        }
    } else { // End of: if ($location_check_passed)
        // Location check failed, set the error message
        $_SESSION['error_message'] = $location_error_message;
    }
} else { // End of: if (!$attendance)
    $_SESSION['error_message'] = "You have already checked in today";
}
header("Location: " . $_SERVER['PHP_SELF']);
exit;
}

// Handle check out
if (isset($_POST['check_out'])) {
    if ($attendance && $attendance['check_in'] && !$attendance['check_out']) {
        // Check if 8 hours have passed since check-in based on server time
        // Get current server time from database to prevent manipulation
        $server_time_query = $conn->query("SELECT NOW() as server_time");
        $server_time_row = $server_time_query->fetch_assoc();
        $server_time = new DateTime($server_time_row['server_time']);

        // Get check-in time from the database
        $check_in_time = new DateTime($attendance['check_in']);

        // Calculate difference in hours
        $time_diff = $server_time->diff($check_in_time);
        $hours_worked = ($time_diff->days * 24) + $time_diff->h + ($time_diff->i / 60);

        if ($hours_worked < 8) {
            // Not enough hours have passed
            $hours_remaining = ceil(8 - $hours_worked);
            $available_checkout = clone $check_in_time;
            $available_checkout->modify('+8 hours');

            $_SESSION['error_message'] = "Work at least 8 hours before checking out. Remaining: " . $hours_remaining . " hours. Available checkout time: " . $available_checkout->format('h:i A');
            header("Location: " . $_SERVER['PHP_SELF']);
            exit;
        }

        try {
            $conn->begin_transaction();

            // Auto end break if still on break
            if ($attendance['break_start'] && !$attendance['break_end']) {
                // Update attendance with break end using server time
                $stmt_break = $conn->prepare("UPDATE attendance SET break_end = NOW() WHERE employee_id = ? AND date = ?");
                $stmt_break->bind_param("is", $employee_id, $today);
                $stmt_break->execute();

                // Update break schedule using server time
                $stmt_break_schedule = $conn->prepare("UPDATE break_schedule SET actual_end = NOW() WHERE employee_id = ? AND break_start = ? AND actual_end IS NULL");
                $stmt_break_schedule->bind_param("is", $employee_id, $attendance['break_start']);
                $stmt_break_schedule->execute();
            }

            // Use server timestamp for consistency and to prevent manipulation
            $stmt = $conn->prepare("UPDATE attendance SET check_out = NOW() WHERE employee_id = ? AND date = ?");
            $stmt->bind_param("is", $employee_id, $today);

            if ($stmt->execute()) {
                $conn->commit();
                $_SESSION['success_message'] = "Check out successful";
            } else {
                throw new Exception("Check out failed");
            }
        } catch (Exception $e) {
            $conn->rollback();
            error_log("Check out error: " . $e->getMessage());
            $_SESSION['error_message'] = "Check out error: " . $e->getMessage();
        }
    } else {
        $_SESSION['error_message'] = "Cannot check out - you must check in first or you may have already checked out";
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Handle break start
if (isset($_POST['break_start'])) {
    if ($attendance && $attendance['check_in'] && !$attendance['check_out'] && !$attendance['break_start']) {
        // Check if at least 30 minutes have passed since check-in
        $check_in_time = new DateTime($attendance['check_in']);
        $server_time_query = $conn->query("SELECT NOW() as server_time");
        $server_time_row = $server_time_query->fetch_assoc();
        $server_time = new DateTime($server_time_row['server_time']);

        $time_diff = $server_time->diff($check_in_time);
        $minutes_worked = ($time_diff->days * 24 * 60) + ($time_diff->h * 60) + $time_diff->i;

        if ($minutes_worked < 30) {
            $_SESSION['error_message'] = "You must work at least 30 minutes before taking a break. Remaining: " . (30 - $minutes_worked) . " minutes.";
            header("Location: " . $_SERVER['PHP_SELF']);
            exit;
        }

        try {
            $conn->begin_transaction();

            // Use server time for break start
            $stmt = $conn->prepare("UPDATE attendance SET break_start = NOW() WHERE employee_id = ? AND date = ?");
            $stmt->bind_param("is", $employee_id, $today);
            $stmt->execute();

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
            $stmt->bind_param("is", $employee_id, $scheduled_end);
            $stmt->execute();

            $conn->commit();
            $_SESSION['success_message'] = "Break start successful";
        } catch (Exception $e) {
            $conn->rollback();
            error_log("Break start error: " . $e->getMessage());
            $_SESSION['error_message'] = "Break start error: " . $e->getMessage();
        }
    } else {
        $_SESSION['error_message'] = "Cannot start break at this time";
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Handle break end
if (isset($_POST['break_end'])) {
    if ($attendance && $attendance['check_in'] && !$attendance['check_out'] && $attendance['break_start'] && !$attendance['break_end']) {
        try {
            $conn->begin_transaction();

            // Use server time for break end
            $stmt = $conn->prepare("UPDATE attendance SET break_end = NOW() WHERE employee_id = ? AND date = ?");
            $stmt->bind_param("is", $employee_id, $today);
            $stmt->execute();

            // Update break schedule with server time
            $stmt = $conn->prepare("UPDATE break_schedule SET actual_end = NOW() WHERE employee_id = ? AND break_start = ? AND actual_end IS NULL");
            $stmt->bind_param("is", $employee_id, $attendance['break_start']);
            $stmt->execute();

            $conn->commit();
            $_SESSION['success_message'] = "Break end successful";
        } catch (Exception $e) {
            $conn->rollback();
            error_log("Break end error: " . $e->getMessage());
            $_SESSION['error_message'] = "Break end error: " . $e->getMessage();
        }
    } else {
        $_SESSION['error_message'] = "Cannot end break at this time";
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Handle reset break (for admin-initiated break reset)
if (isset($_POST['reset_break'])) {
    if ($attendance && $attendance['check_in'] && !$attendance['check_out']) {
        try {
            $conn->begin_transaction();

            // If in break, end it first
            if ($attendance['break_start'] && !$attendance['break_end']) {
                // End the current break
                $stmt = $conn->prepare("UPDATE attendance SET break_end = NOW() WHERE employee_id = ? AND date = ?");
                $stmt->bind_param("is", $employee_id, $today);
                $stmt->execute();

                // Update break schedule
                $stmt = $conn->prepare("UPDATE break_schedule SET actual_end = NOW() WHERE employee_id = ? AND break_start = ? AND actual_end IS NULL");
                $stmt->bind_param("is", $employee_id, $attendance['break_start']);
                $stmt->execute();
            }

            $conn->commit();
            $_SESSION['success_message'] = "Break reset successful";
        } catch (Exception $e) {
            $conn->rollback();
            error_log("Break reset error: " . $e->getMessage());
            $_SESSION['error_message'] = "Break reset error: " . $e->getMessage();
        }
    } else {
        $_SESSION['error_message'] = "Cannot reset break at this time";
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Display messages from session
$message = '';
$error = '';

if (isset($_SESSION['success_message'])) {
    $message = $_SESSION['success_message'];
    unset($_SESSION['success_message']);
}

if (isset($_SESSION['error_message'])) {
    $error = $_SESSION['error_message'];
    unset($_SESSION['error_message']);
}

// Refresh attendance data
$attendance_stmt->execute();
$attendance_result = $attendance_stmt->get_result();
$attendance = $attendance_result->fetch_assoc();

// Calculate remaining break time and get break schedule details
$break_remaining = '';
$break_minutes_remaining = 0;
$break_seconds_remaining = 0;
$break_timer_started = false;
$break_schedule = null;

// تعريف المتغيرات الافتراضية قبل أي استخدام
$scheduled_end_time = null;
$remaining_negative = false;
$remaining_minutes = 0;
$remaining_seconds = 0;

if ($attendance && $attendance['break_start'] && !$attendance['break_end']) {
    // Get server time for accurate calculations
    $server_time_query = $conn->query("SELECT NOW() as server_time");
    $server_time_row = $server_time_query->fetch_assoc();
    $now = new DateTime($server_time_row['server_time']);
    $break_start = new DateTime($attendance['break_start']);

    // Get scheduled end time and other break details from break_schedule
    $break_schedule_stmt = $conn->prepare("
        SELECT *
        FROM break_schedule 
        WHERE employee_id = ? 
        AND break_start <= ? 
        AND actual_end IS NULL
        ORDER BY break_start DESC
        LIMIT 1
    ");
    $break_schedule_stmt->bind_param("is", $employee_id, $attendance['break_start']);
    $break_schedule_stmt->execute();
    $break_schedule_result = $break_schedule_stmt->get_result();

    if ($break_schedule = $break_schedule_result->fetch_assoc()) {
        if (isset($break_schedule['scheduled_end']) && $break_schedule['scheduled_end']) {
            $scheduled_end_time = new DateTime($break_schedule['scheduled_end']);
            $time_exceeded = $scheduled_end_time < $now;
            $remaining = $now->diff($scheduled_end_time);
            $remaining_negative = $time_exceeded;
            $remaining_minutes = intval(($remaining->days * 24 * 60) + ($remaining->h * 60) + $remaining->i);
            $remaining_seconds = intval($remaining->s);
            if ($remaining_negative) {
                // إذا تجاوز الوقت، احسب الفرق بشكل صحيح
                $remaining_minutes = abs($remaining_minutes);
                $remaining_seconds = abs($remaining_seconds);
            }
        } else {
            // fallback
            $scheduled_end_time = null;
            $remaining_negative = false;
            $remaining_minutes = 0;
            $remaining_seconds = 0;
        }
    } else {
        $scheduled_end_time = null;
        $remaining_negative = false;
        $remaining_minutes = 0;
        $remaining_seconds = 0;
    }
}

// Calculate next available check-in time if needed
$next_checkin_time = '';
if (!$attendance && $last_attendance && $last_attendance['check_out']) {
    $last_checkout = new DateTime($last_attendance['check_out']);
    $now = new DateTime();
    $hours_diff = $last_checkout->diff($now);
    $total_hours = $hours_diff->h + ($hours_diff->days * 24);

    if ($total_hours < 6) {
        $next_checkin = clone $last_checkout;
        $next_checkin->modify('+6 hours');
        $next_checkin_time = $next_checkin->format('h:i A');
    }
}

// Add this function to calculate distance between two coordinates using Haversine formula
function calculateDistance($lat1, $lon1, $lat2, $lon2)
{
    // Earth's radius in kilometers
    $earth_radius = 6371;

    $dLat = deg2rad($lat2 - $lat1);
    $dLon = deg2rad($lon2 - $lon1);

    $a = sin($dLat / 2) * sin($dLat / 2) + cos(deg2rad($lat1)) * cos(deg2rad($lat2)) * sin($dLon / 2) * sin($dLon / 2);
    $c = 2 * asin(sqrt($a));

    return $earth_radius * $c; // Distance in kilometers
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Employee Attendance</title>
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
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        }

        .dashboard-header {
            background: var(--primary-gradient);
            color: white;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 6px 15px rgba(0, 0, 0, 0.08);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
        }

        .dashboard-header h2 {
            margin: 0;
            font-weight: 600;
            font-size: 1.8rem;
        }

        .card {
            border: none;
            border-radius: 12px;
            box-shadow: 0 6px 15px rgba(0, 0, 0, 0.08);
            overflow: hidden;
            margin-bottom: 20px;
        }

        .card-header {
            background: var(--primary-gradient);
            color: white;
            border-bottom: none;
            padding: 15px 20px;
            font-weight: 600;
        }

        .btn {
            padding: 8px 15px;
            font-size: 0.9rem;
            border-radius: 8px;
            margin-bottom: 10px;
            transition: all 0.3s;
        }

        .btn-primary {
            background: var(--primary-gradient);
            border: none;
            font-weight: 500;
            box-shadow: 0 3px 5px rgba(0, 0, 0, 0.15);
        }

        .btn-primary:hover:not([disabled]) {
            background: linear-gradient(135deg, var(--primary-dark) 0%, var(--secondary-color) 100%);
            transform: translateY(-2px);
            box-shadow: 0 5px 10px rgba(0, 0, 0, 0.2);
        }

        .btn-success {
            background-color: #10b981;
            border: none;
        }

        .btn-success:hover:not([disabled]) {
            background-color: #059669;
            transform: translateY(-2px);
        }

        .btn-danger {
            background-color: #ef4444;
            border: none;
        }

        .btn-danger:hover:not([disabled]) {
            background-color: #dc2626;
            transform: translateY(-2px);
        }

        .btn-warning {
            background-color: #f59e0b;
            border: none;
            color: white;
        }

        .btn-warning:hover:not([disabled]) {
            background-color: #d97706;
            color: white;
            transform: translateY(-2px);
        }

        .btn-info {
            background-color: #3b82f6;
            border: none;
            color: white;
        }

        .btn-info:hover:not([disabled]) {
            background-color: #2563eb;
            color: white;
            transform: translateY(-2px);
        }

        .btn-secondary {
            background-color: #6b7280;
            border: none;
        }

        .btn-secondary:hover:not([disabled]) {
            background-color: #4b5563;
            transform: translateY(-2px);
        }

        .btn[disabled] {
            opacity: 0.6;
            cursor: not-allowed;
        }

        .badge {
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 0.85rem;
            font-weight: 500;
        }

        .alert {
            border-radius: 10px;
            padding: 15px 20px;
            margin-bottom: 20px;
            border: none;
        }

        .alert-success {
            background-color: #d1fae5;
            color: #065f46;
        }

        .alert-danger {
            background-color: #fee2e2;
            color: #b91c1c;
        }

        .table {
            margin-bottom: 0;
            border-radius: 8px;
            overflow: hidden;
            border-collapse: separate;
            border-spacing: 0;
        }

        .table th {
            background: var(--primary-gradient);
            color: white;
            font-weight: 500;
            border: none;
            padding: 12px 15px;
            text-transform: uppercase;
            font-size: 0.85rem;
            letter-spacing: 0.5px;
        }

        .table td {
            vertical-align: middle;
            padding: 12px 15px;
            border-bottom: 1px solid #f1f1f1;
            color: #555;
        }

        .table tr:last-child td {
            border-bottom: none;
        }

        .table-striped tbody tr:nth-of-type(odd) {
            background-color: rgba(var(--primary-color), 0.05);
        }

        .table-responsive {
            border-radius: 8px;
            overflow: hidden;
        }

        /* Card with shadow effect */
        .card {
            border: none;
            border-radius: 12px;
            box-shadow: 0 6px 15px rgba(0, 0, 0, 0.08);
            overflow: hidden;
            margin-bottom: 30px;
            border-top: 5px solid var(--primary-color);
            transition: transform 0.3s ease;
        }

        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.12);
        }

        .table-container {
            background-color: #fff;
            border-radius: 12px;
            box-shadow: 0 6px 15px rgba(0, 0, 0, 0.08);
            padding: 20px;
            margin-bottom: 30px;
            overflow: hidden;
            border-top: 5px solid #6a11cb;
            transition: transform 0.3s ease;
        }

        .table-container:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.12);
        }

        .table-container h4 {
            color: #4a4a4a;
            font-size: 1.2rem;
            font-weight: 600;
            margin-bottom: 20px;
            border-bottom: 1px solid #f0f0f0;
            padding-bottom: 10px;
        }

        .info-card {
            background-color: white;
            border-radius: 12px;
            padding: 20px;
            height: 100%;
            box-shadow: 0 6px 15px rgba(0, 0, 0, 0.08);
            transition: transform 0.3s ease;
            border-top: 5px solid #6a11cb;
        }

        .info-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.12);
        }

        .info-card h4 {
            color: #4a4a4a;
            font-size: 1.2rem;
            font-weight: 600;
            margin-bottom: 20px;
            border-bottom: 1px solid #f0f0f0;
            padding-bottom: 10px;
        }

        .info-card p {
            margin-bottom: 12px;
            color: #666;
        }

        .info-card p strong {
            color: #333;
            font-weight: 600;
        }

        .break-timer {
            background: linear-gradient(135deg, #ff4d4d 0%, #f43f5e 100%);
            color: white;
            padding: 10px 15px;
            border-radius: 8px;
            font-weight: 500;
            text-align: center;
            margin-top: 10px;
            box-shadow: 0 4px 6px rgba(244, 63, 94, 0.2);
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% {
                opacity: 0.8;
            }

            50% {
                opacity: 1;
            }

            100% {
                opacity: 0.8;
            }
        }

        .status-badge {
            font-size: 1rem;
            padding: 8px 15px;
            border-radius: 8px;
        }

        .action-buttons {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin: 25px auto;
            justify-content: center;
            max-width: 700px;
        }

        .action-buttons form {
            flex: 0 0 calc(50% - 10px);
            max-width: calc(50% - 10px);
        }

        .action-buttons .btn {
            padding: 18px;
            font-size: 1.1rem;
            font-weight: 600;
            border-radius: 12px;
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.15);
            transition: all 0.3s ease;
            width: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            letter-spacing: 0.5px;
        }

        .action-buttons .btn i {
            font-size: 1.3rem;
            margin-right: 10px;
        }

        .action-buttons .btn:hover:not([disabled]) {
            transform: translateY(-3px);
            box-shadow: 0 6px 15px rgba(0, 0, 0, 0.2);
        }

        .action-buttons .btn-primary {
            background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%);
            border: none;
        }

        .action-buttons .btn-danger {
            background: linear-gradient(135deg, #f43f5e 0%, #ef4444 100%);
            border: none;
        }

        /* Large screens */
        @media (min-width: 1200px) {
            .action-buttons {
                max-width: 800px;
            }

            .action-buttons .btn {
                padding: 18px;
                font-size: 1.2rem;
            }
        }

        /* Medium screens */
        @media (max-width: 992px) {
            .action-buttons {
                max-width: 600px;
                gap: 15px;
            }

            .action-buttons .btn {
                padding: 15px;
                font-size: 1rem;
            }
        }

        /* Mobile optimizations */
        @media (max-width: 768px) {
            .container {
                padding-left: 10px;
                padding-right: 10px;
                max-width: 100%;
            }

            .dashboard-header {
                align-items: center !important;
                padding: 15px;
            }

            .dashboard-header h2 {
                font-size: 1.5rem;
            }

            .dashboard-header .btn {
                width: 100%;
                margin-top: 10px;
            }

            .card-body {
                padding: 15px;
            }

            .card-header {
                padding: 12px 15px;
            }

            .info-card {
                margin-bottom: 15px;
                padding: 15px;
            }

            .info-card h4 {
                font-size: 1.1rem;
            }

            .table-container {
                padding: 15px;
            }

            .table th,
            .table td {
                padding: 10px 8px;
                font-size: 0.85rem;
            }

            .alert {
                padding: 12px;
                font-size: 0.9rem;
            }

            /* Button styles for medium screens */
            .action-buttons {
                max-width: 500px;
                gap: 15px;
                margin: 20px auto;
            }

            .action-buttons .btn {
                padding: 14px;
                font-size: 0.95rem;
            }
        }

        /* Small device optimizations */
        @media (max-width: 576px) {
            body {
                padding-bottom: 20px;
            }

            .py-4 {
                padding-top: 10px !important;
                padding-bottom: 10px !important;
            }

            .row {
                margin-left: -8px;
                margin-right: -8px;
            }

            .col-md-6 {
                padding-left: 8px;
                padding-right: 8px;
            }

            .card-header {
                padding: 10px 12px;
                font-size: 0.95rem;
            }

            .card-body {
                padding: 12px;
            }

            .info-card {
                padding: 12px;
                margin-bottom: 12px;
            }

            .info-card h4 {
                font-size: 1rem;
                margin-bottom: 12px;
                padding-bottom: 8px;
            }

            .break-timer {
                font-size: 0.9rem;
                padding: 8px 10px;
            }

            .table-container {
                padding: 12px;
                margin-bottom: 15px;
            }

            .table-container h4 {
                font-size: 1rem;
                margin-bottom: 12px;
            }

            .table-responsive {
                margin-left: -5px;
                margin-right: -5px;
                width: calc(100% + 10px);
            }

            .table th,
            .table td {
                padding: 8px 5px;
                font-size: 0.75rem;
                white-space: nowrap;
            }

            .alert {
                padding: 10px;
                font-size: 0.85rem;
                margin-bottom: 12px;
            }

            .badge {
                font-size: 0.7rem;
                padding: 5px 8px;
            }

            .alert-info {
                font-size: 0.85rem;
                line-height: 1.5;
                padding: 12px;
            }

            .alert-info strong {
                display: block;
                margin-bottom: 5px;
            }

            /* Button styles for small screens */
            .action-buttons {
                flex-direction: column;
                gap: 12px;
                margin: 15px auto;
            }

            .action-buttons form {
                flex: 0 0 100%;
                max-width: 100%;
            }

            .check-in-form .btn,
            .check-out-form .btn {
                height: 55px;
                font-size: 1rem;
                font-weight: bold;
                border-radius: 10px;
                margin-bottom: 0;
            }
        }

        /* Very small screens */
        @media (max-width: 360px) {
            .dashboard-header h2 {
                font-size: 1.3rem;
            }

            .card-header {
                font-size: 0.9rem;
            }

            .table th,
            .table td {
                padding: 6px 4px;
                font-size: 0.7rem;
            }

            /* Button styles for very small screens */
            .action-buttons {
                gap: 10px;
                margin: 12px auto;
            }

            .check-in-form .btn,
            .check-out-form .btn {
                height: 50px;
                font-size: 0.9rem;
                padding: 10px;
            }

            .action-buttons .btn i {
                font-size: 1rem;
                margin-right: 8px;
            }
        }

        /* Timeline Table Styles */
        .timeline-container {
            background-color: #fff;
            border-radius: 12px;
            box-shadow: 0 6px 15px rgba(0, 0, 0, 0.08);
            padding: 20px;
            margin-bottom: 30px;
            overflow: hidden;
            border-top: 5px solid var(--primary-color);
            transition: transform 0.3s ease;
        }

        .timeline-container:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.12);
        }

        .timeline-container h4 {
            color: #4a4a4a;
            font-size: 1.2rem;
            font-weight: 600;
            margin-bottom: 20px;
            border-bottom: 1px solid #f0f0f0;
            padding-bottom: 10px;
            display: flex;
            align-items: center;
        }

        .timeline-container h4 i {
            margin-right: 10px;
            color: var(--primary-color);
        }

        .timeline-table {
            margin-bottom: 0;
            border-radius: 8px;
            overflow: hidden;
            border-collapse: separate;
            border-spacing: 0;
            width: 100%;
            border: 1px solid rgba(var(--primary-color), 0.2);
        }

        .timeline-table th {
            background: var(--primary-gradient);
            color: white;
            font-weight: 500;
            border: none;
            padding: 12px 15px;
            text-transform: uppercase;
            font-size: 0.85rem;
            letter-spacing: 0.5px;
            text-align: center;
        }

        .timeline-table td {
            vertical-align: middle;
            padding: 12px 15px;
            border-bottom: 1px solid #f1f1f1;
            color: #555;
            text-align: center;
            font-weight: 500;
        }

        .timeline-table tr:last-child td {
            border-bottom: none;
        }

        .timeline-table td.highlight {
            font-weight: bold;
            color: #333;
            position: relative;
            overflow: hidden;
        }

        .timeline-table td.highlight::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            width: 100%;
            height: 3px;
            background: var(--primary-gradient);
            opacity: 0.5;
        }

        .timeline-table td.empty {
            color: #aaa;
            font-style: italic;
        }

        /* Timeline animation */
        @keyframes timeline-glow {
            0% {
                box-shadow: 0 0 10px rgba(var(--primary-color), 0.2);
            }

            50% {
                box-shadow: 0 0 20px rgba(var(--primary-color), 0.4);
            }

            100% {
                box-shadow: 0 0 10px rgba(var(--primary-color), 0.2);
            }
        }

        .timeline-container {
            animation: timeline-glow 3s infinite;
        }

        /* Timeline responsive styles */
        @media (max-width: 992px) {
            .timeline-container {
                padding: 15px;
            }

            .timeline-table th,
            .timeline-table td {
                padding: 10px;
                font-size: 0.9rem;
            }
        }

        @media (max-width: 768px) {
            .timeline-container h4 {
                font-size: 1.1rem;
                margin-bottom: 15px;
            }

            .timeline-table th,
            .timeline-table td {
                padding: 8px;
                font-size: 0.85rem;
            }
        }

        @media (max-width: 576px) {
            .timeline-container {
                padding: 12px;
                margin-bottom: 20px;
            }

            .timeline-container h4 {
                font-size: 1rem;
                margin-bottom: 12px;
                padding-bottom: 8px;
            }

            .timeline-table {
                min-width: 450px;
                /* Ensure minimum width for small screens */
            }

            .timeline-table th,
            .timeline-table td {
                padding: 8px 5px;
                font-size: 0.75rem;
                white-space: nowrap;
            }

            .timeline-scroll {
                overflow-x: auto;
                margin-left: -5px;
                margin-right: -5px;
                padding-bottom: 5px;
            }
        }

        @media (max-width: 360px) {
            .timeline-container {
                padding: 10px;
            }

            .timeline-table th,
            .timeline-table td {
                padding: 6px 4px;
                font-size: 0.7rem;
            }
        }

        /* Card with theme-colored border */
        .card {
            border: none;
            border-radius: 12px;
            box-shadow: 0 6px 15px rgba(0, 0, 0, 0.08);
            overflow: hidden;
            margin-bottom: 30px;
            border-top: 5px solid var(--primary-color);
            transition: transform 0.3s ease;
        }

        /* Table container with themed border */
        .table-container {
            background-color: #fff;
            border-radius: 12px;
            box-shadow: 0 6px 15px rgba(0, 0, 0, 0.08);
            padding: 20px;
            margin-bottom: 30px;
            overflow: hidden;
            border-top: 5px solid var(--primary-color);
            transition: transform 0.3s ease;
        }

        /* Info card with themed border */
        .info-card {
            background-color: white;
            border-radius: 12px;
            padding: 20px;
            height: 100%;
            box-shadow: 0 6px 15px rgba(0, 0, 0, 0.08);
            transition: transform 0.3s ease;
            border-top: 5px solid var(--primary-color);
        }

        /* Remove RTL support */
        .btn i {
            margin-right: 5px;
            margin-left: 0;
        }

        .me-2 {
            margin-right: 0.5rem !important;
            margin-left: 0 !important;
        }

        .ms-2 {
            margin-left: 0.5rem !important;
            margin-right: 0 !important;
        }

        /* Pulse animation for the request location button */
        @keyframes btn-pulse {
            0% {
                box-shadow: 0 0 0 0 rgba(var(--primary-color), 0.7);
                transform: scale(1);
            }

            70% {
                box-shadow: 0 0 0 10px rgba(var(--primary-color), 0);
                transform: scale(1.05);
            }

            100% {
                box-shadow: 0 0 0 0 rgba(var(--primary-color), 0);
                transform: scale(1);
            }
        }

        .btn-pulse {
            animation: btn-pulse 1.5s infinite;
            box-shadow: 0 0 0 0 rgba(var(--primary-color), 1);
        }

        #request_location_btn {
            transition: all 0.3s ease;
            border-radius: 8px;
            position: relative;
            overflow: hidden;
        }

        #request_location_btn:before {
            content: "";
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: rgba(255, 255, 255, .2);
            transform: rotate(30deg);
            opacity: 0;
            transition: opacity 0.3s;
        }

        #request_location_btn:hover:before {
            opacity: 1;
        }
    </style>
</head>

<body>
    <div class="container py-4">
        <div class="dashboard-header">
            <h2><i class="bi bi-clock-history me-2"></i>Attendance System</h2>
            <div>
                <button type="button" class="btn btn-light me-2" data-bs-toggle="modal" data-bs-target="#themeModal">
                    <i class="bi bi-palette-fill me-1"></i>Theme
                </button>
                <a href="employee_tasks.php" class="btn btn-info me-2">
                    <i class="bi bi-list-check me-1"></i>My Tasks
                </a>
                <a href="logout.php" class="btn btn-danger">
                    <i class="bi bi-box-arrow-right me-1"></i>Logout
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

        <?php if ($error): ?>
            <div class="alert alert-danger alert-dismissible fade show">
                <i class="bi bi-exclamation-triangle-fill me-2"></i>
                <?= htmlspecialchars($error) ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>

        <div class="row">
            <!-- Employee Info Card -->
            <div class="col-md-6 mb-4">
                <div class="info-card">
                    <h4><i class="bi bi-person-badge me-2"></i>Employee Information</h4>
                    <p><strong>Name:</strong> <span class="text-dark"><?= htmlspecialchars($employee['name']) ?></span></p>
                    <p><strong>Email:</strong> <span class="text-dark"><?= htmlspecialchars($employee['email']) ?></span></p>
                    <p class="mb-0"><strong>ID:</strong> <span class="text-dark"><?= $employee['id'] ?></span></p>
                </div>
            </div>

            <!-- Status Card -->
            <div class="col-md-6 mb-4">
                <div class="info-card">
                    <h4><i class="bi bi-calendar-check me-2"></i>Today's Status</h4>
                    <p><strong>Date:</strong> <span class="text-dark"><?= date('l, F j, Y', strtotime($today)) ?></span></p>
                    <p>
                        <strong>Status:</strong>
                        <?php
                        if (!$attendance) {
                            echo '<span class="badge bg-secondary">Not Checked In</span>';
                        } elseif ($attendance['check_out']) {
                            echo '<span class="badge bg-success">Checked Out</span>';
                        } elseif ($attendance['break_start'] && !$attendance['break_end']) {
                            echo '<span class="badge bg-warning text-dark">On Break</span>';
                        } else {
                            echo '<span class="badge bg-primary">Checked In</span>';
                        }
                        ?>
                    </p>

                    <?php if ($attendance && $attendance['break_start'] && !$attendance['break_end']): ?>
                        <!-- Currently on break - show break timer -->
                        <div class="alert alert-warning text-center p-4 mb-4">
                            <h4><i class="bi bi-hourglass-split me-2"></i>You're currently on a break</h4>
                            <?php
                            // Use server time for consistency
                            $server_time_query = $conn->query("SELECT NOW() as server_time");
                            $server_time_row = $server_time_query->fetch_assoc();
                            $server_now = new DateTime($server_time_row['server_time']);

                            $break_start = new DateTime($attendance['break_start']);
                            $break_duration = $server_now->diff($break_start);
                            $break_minutes = ($break_duration->h * 60) + $break_duration->i;
                            $break_seconds = $break_duration->s;

                            // Check if break time exceeded 15 minutes
                            $break_exceeded = $break_minutes > 15;
                            if ($break_exceeded) {
                                // Create admin alert for extended break
                                $alert_message = "Employee #$employee_id has exceeded break time limit. Break started at " . $break_start->format('h:i A') . " and has lasted " . $break_minutes . " minutes.";
                                $alert_stmt = $conn->prepare("INSERT INTO admin_alerts (employee_id, message, device_info, is_read, severity) VALUES (?, ?, 'System auto-end', 0, 'high')");
                                $alert_stmt->bind_param("is", $employee_id, $alert_message);
                                $alert_stmt->execute();

                                // Auto end the break
                                $stmt_break = $conn->prepare("UPDATE attendance SET break_end = NOW() WHERE employee_id = ? AND date = ? AND break_start IS NOT NULL AND break_end IS NULL");
                                $stmt_break->bind_param("is", $employee_id, $today);
                                $stmt_break->execute();

                                // Update break schedule
                                $stmt_break_schedule = $conn->prepare("UPDATE break_schedule SET actual_end = NOW() WHERE employee_id = ? AND actual_end IS NULL");
                                $stmt_break_schedule->bind_param("i", $employee_id);
                                $stmt_break_schedule->execute();

                                // Show warning message
                                echo '<div class="alert alert-danger mt-3">
                                    <i class="bi bi-exclamation-triangle-fill me-2"></i>
                                    <strong>Warning:</strong> Your break has been automatically ended because it exceeded the 15-minute limit.
                                </div>';
                                
                                // Reload the page after 3 seconds
                                echo '<script>
                                    setTimeout(function() {
                                        window.location.reload();
                                    }, 3000);
                                </script>';
                            }
                            ?>
                            <div class="break-time-counter mt-3 mb-3">
                                <span class="fs-1 text-dark" id="currentBreakDuration">
                                    <?= sprintf('%02d:%02d', $break_minutes, $break_seconds) ?>
                                </span>
                                <div class="mt-2 text-muted">Current break duration</div>

                                <?php if ($break_exceeded): ?>
                                    <div class="alert alert-danger mt-3">
                                        <i class="bi bi-exclamation-circle-fill me-2"></i>
                                        Break time exceeded by <?= $break_minutes - 15 ?> minutes
                                    </div>
                                <?php endif; ?>

                                <?php if ($scheduled_end_time): ?>
                                    <div class="mt-3 pt-3 border-top">
                                        <div class="badge bg-<?= $remaining_negative ? 'danger' : 'info' ?> p-2 mb-2">
                                            <i class="bi bi-alarm me-1"></i>
                                            Scheduled End: <?= $scheduled_end_time->format('h:i:s A') ?>
                                        </div>
                                        <div class="mt-2">
                                            <span class="badge bg-<?= $remaining_negative ? 'danger' : 'warning' ?> p-2" id="breakRemainingTime">
                                                <?php if ($remaining_negative): ?>
                                                    Break time exceeded by <?= sprintf('%02d:%02d', $remaining_minutes, $remaining_seconds) ?>
                                                <?php else: ?>
                                                    <?= sprintf('%02d:%02d', $remaining_minutes, $remaining_seconds) ?> remaining
                                                <?php endif; ?>
                                            </span>
                                        </div>
                                    </div>
                                <?php endif; ?>
                            </div>
                            <form method="POST" action="" class="mt-3">
                                <button type="submit" name="break_end" class="btn btn-success btn-lg">
                                    <i class="bi bi-check-circle-fill me-2"></i>End Break
                                </button>
                            </form>
                        </div>

                        <script>
                        // Auto end break after 15 minutes
                        document.addEventListener('DOMContentLoaded', function() {
                            const breakStartTime = new Date('<?= $attendance['break_start'] ?>');
                            const fifteenMinutes = 15 * 60 * 1000; // 15 minutes in milliseconds
                            const endTime = new Date(breakStartTime.getTime() + fifteenMinutes);
                            
                            function checkBreakTime() {
                                const now = new Date();
                                if (now >= endTime) {
                                    // Break time is up, automatically end the break
                                    fetch('auto_end_break.php', {
                                        method: 'POST',
                                        headers: {
                                            'Content-Type': 'application/json',
                                        },
                                        body: JSON.stringify({
                                            employee_id: <?= $employee_id ?>,
                                            date: '<?= $today ?>',
                                            exceeded: true
                                        })
                                    })
                                    .then(response => response.json())
                                    .then(data => {
                                        if (data.success) {
                                            // Show notification
                                            if ('Notification' in window && Notification.permission === 'granted') {
                                                new Notification('Break Time Ended', {
                                                    body: 'Your break has been automatically ended because it exceeded the 15-minute limit.',
                                                    icon: '/favicon.ico'
                                                });
                                            }
                                            
                                            // Play sound alert
                                            try {
                                                const audio = new Audio('/assets/alert.mp3');
                                                audio.play().catch(e => console.log('Sound play error:', e));
                                            } catch (e) {
                                                console.error('Audio play error:', e);
                                            }
                                            
                                            // Show warning message
                                            const warningDiv = document.createElement('div');
                                            warningDiv.className = 'alert alert-danger mt-3';
                                            warningDiv.innerHTML = `
                                                <i class="bi bi-exclamation-triangle-fill me-2"></i>
                                                <strong>Warning:</strong> Your break has been automatically ended because it exceeded the 15-minute limit.
                                            `;
                                            document.querySelector('.break-time-counter').appendChild(warningDiv);
                                            
                                            // Reload the page after 3 seconds
                                            setTimeout(() => {
                                                window.location.reload();
                                            }, 3000);
                                        } else {
                                            console.error('Failed to auto-end break:', data.error);
                                        }
                                    })
                                    .catch(error => {
                                        console.error('Error auto-ending break:', error);
                                    });
                                }
                            }

                            // Check every second
                            setInterval(checkBreakTime, 1000);
                        });
                        </script>
                    <?php endif; ?>

                    <?php if (!$attendance && isset($next_checkin_time) && $next_checkin_time): ?>
                        <div class="alert alert-info mt-3 mb-0">
                            <i class="bi bi-info-circle-fill me-2"></i>
                            Next check-in available at: <strong><?= $next_checkin_time ?></strong>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- Action Buttons -->
        <div class="card mb-4">
            <div class="card-header">
                <i class="bi bi-toggles me-2"></i>Available Actions
            </div>
            <div class="card-body">
                <?php if ($attendance && $attendance['check_in'] && !$attendance['check_out']): ?>
                    <div class="alert alert-info mb-3">
                        <i class="bi bi-info-circle-fill me-2"></i>
                        <strong>Note:</strong> Work at least 8 hours before checking out.
                        <?php
                        if ($attendance['check_in']) {
                            // Get current server time from database
                            $server_time_query = $conn->query("SELECT NOW() as server_time");
                            $server_time_row = $server_time_query->fetch_assoc();
                            $server_time = new DateTime($server_time_row['server_time']);

                            // Calculate time difference using server time
                            $check_in_time = new DateTime($attendance['check_in']);
                            $time_diff = $server_time->diff($check_in_time);
                            $hours_worked = ($time_diff->days * 24) + $time_diff->h + ($time_diff->i / 60);
                            $hours_remaining = max(0, 10 - $hours_worked);

                            if ($hours_remaining > 0) {
                                $available_checkout = clone $check_in_time;
                                $available_checkout->modify('+8 hours');
                                echo " Worked " . floor($hours_worked) . " hours and " . ($time_diff->i) . " minutes. You can check out at " . $available_checkout->format('h:i A') . ".";
                            } else {
                                echo " You've completed the minimum required (8 hours) and can check out now.";
                            }
                        }
                        ?>
                    </div>

                    <?php if ($attendance['break_start'] && !$attendance['break_end']): ?>
                        <!-- Currently on break - show break timer -->
                        <div class="alert alert-warning text-center p-4 mb-4">
                            <h4><i class="bi bi-hourglass-split me-2"></i>You're currently on a break</h4>
                            <?php
                            // Use server time for consistency
                            $server_time_query = $conn->query("SELECT NOW() as server_time");
                            $server_time_row = $server_time_query->fetch_assoc();
                            $server_now = new DateTime($server_time_row['server_time']);

                            $break_start = new DateTime($attendance['break_start']);
                            $break_duration = $server_now->diff($break_start);
                            $break_minutes = ($break_duration->h * 60) + $break_duration->i;
                            $break_seconds = $break_duration->s;

                            // Check if break time exceeded 15 minutes
                            $break_exceeded = $break_minutes > 15;
                            if ($break_exceeded) {
                                // Create admin alert for extended break
                                $alert_message = "Employee #$employee_id has exceeded break time limit. Break started at " . $break_start->format('h:i A') . " and has lasted " . $break_minutes . " minutes.";
                                $alert_stmt = $conn->prepare("
                                    INSERT INTO admin_alerts (employee_id, message, device_info, is_read, severity) 
                                    VALUES (?, ?, 'System auto-end', 0, 'high')
                                ");
                                $alert_stmt->bind_param("is", $employee_id, $alert_message);
                                $alert_stmt->execute();

                                // Auto end the break
                                $stmt_break = $conn->prepare("UPDATE attendance SET break_end = NOW() WHERE employee_id = ? AND date = ? AND break_start IS NOT NULL AND break_end IS NULL");
                                $stmt_break->bind_param("is", $employee_id, $today);
                                $stmt_break->execute();

                                // Update break schedule
                                $stmt_break_schedule = $conn->prepare("UPDATE break_schedule SET actual_end = NOW() WHERE employee_id = ? AND actual_end IS NULL");
                                $stmt_break_schedule->bind_param("i", $employee_id);
                                $stmt_break_schedule->execute();

                                // Show warning message
                                echo '<div class="alert alert-danger mt-3">
                                    <i class="bi bi-exclamation-triangle-fill me-2"></i>
                                    <strong>Warning:</strong> Your break has been automatically ended because it exceeded the 15-minute limit.
                                </div>';
                                
                                // Reload the page after 3 seconds
                                echo '<script>
                                    setTimeout(function() {
                                        window.location.reload();
                                    }, 3000);
                                </script>';
                            }
                            ?>
                            <div class="break-time-counter mt-3 mb-3">
                                <span class="fs-1 text-dark" id="currentBreakDuration">
                                    <?= sprintf('%02d:%02d', $break_minutes, $break_seconds) ?>
                                </span>
                                <div class="mt-2 text-muted">Current break duration</div>

                                <?php if ($break_exceeded): ?>
                                    <div class="alert alert-danger mt-3">
                                        <i class="bi bi-exclamation-circle-fill me-2"></i>
                                        Break time exceeded by <?= $break_minutes - 15 ?> minutes
                                    </div>
                                <?php endif; ?>

                                <?php if ($scheduled_end_time): ?>
                                    <div class="mt-3 pt-3 border-top">
                                        <div class="badge bg-<?= $remaining_negative ? 'danger' : 'info' ?> p-2 mb-2">
                                            <i class="bi bi-alarm me-1"></i>
                                            Scheduled End: <?= $scheduled_end_time->format('h:i:s A') ?>
                                        </div>
                                        <div class="mt-2">
                                            <span class="badge bg-<?= $remaining_negative ? 'danger' : 'warning' ?> p-2" id="breakRemainingTime">
                                                <?php if ($remaining_negative): ?>
                                                    Break time exceeded by <?= sprintf('%02d:%02d', $remaining_minutes, $remaining_seconds) ?>
                                                <?php else: ?>
                                                    <?= sprintf('%02d:%02d', $remaining_minutes, $remaining_seconds) ?> remaining
                                                <?php endif; ?>
                                            </span>
                                        </div>
                                    </div>
                                <?php endif; ?>
                            </div>
                            <form method="POST" action="" class="mt-3">
                                <button type="submit" name="break_end" class="btn btn-success btn-lg">
                                    <i class="bi bi-check-circle-fill me-2"></i>End Break
                                </button>
                            </form>
                        </div>

                        <script>
                        // Auto end break after 15 minutes
                        document.addEventListener('DOMContentLoaded', function() {
                            const breakStartTime = new Date('<?= $attendance['break_start'] ?>');
                            const fifteenMinutes = 15 * 60 * 1000; // 15 minutes in milliseconds
                            const endTime = new Date(breakStartTime.getTime() + fifteenMinutes);
                            
                            function checkBreakTime() {
                                const now = new Date();
                                if (now >= endTime) {
                                    // Break time is up, automatically end the break
                                    fetch('auto_end_break.php', {
                                        method: 'POST',
                                        headers: {
                                            'Content-Type': 'application/json',
                                        },
                                        body: JSON.stringify({
                                            employee_id: <?= $employee_id ?>,
                                            date: '<?= $today ?>',
                                            exceeded: true
                                        })
                                    })
                                    .then(response => response.json())
                                    .then(data => {
                                        if (data.success) {
                                            // Show notification
                                            if ('Notification' in window && Notification.permission === 'granted') {
                                                new Notification('Break Time Ended', {
                                                    body: 'Your break has been automatically ended because it exceeded the 15-minute limit.',
                                                    icon: '/favicon.ico'
                                                });
                                            }
                                            
                                            // Play sound alert
                                            try {
                                                const audio = new Audio('/assets/alert.mp3');
                                                audio.play().catch(e => console.log('Sound play error:', e));
                                            } catch (e) {
                                                console.error('Audio play error:', e);
                                            }
                                            
                                            // Show warning message
                                            const warningDiv = document.createElement('div');
                                            warningDiv.className = 'alert alert-danger mt-3';
                                            warningDiv.innerHTML = `
                                                <i class="bi bi-exclamation-triangle-fill me-2"></i>
                                                <strong>Warning:</strong> Your break has been automatically ended because it exceeded the 15-minute limit.
                                            `;
                                            document.querySelector('.break-time-counter').appendChild(warningDiv);
                                            
                                            // Reload the page after 3 seconds
                                            setTimeout(() => {
                                                window.location.reload();
                                            }, 3000);
                                        } else {
                                            console.error('Failed to auto-end break:', data.error);
                                        }
                                    })
                                    .catch(error => {
                                        console.error('Error auto-ending break:', error);
                                    });
                                }
                            }

                            // Check every second
                            setInterval(checkBreakTime, 1000);
                        });
                        </script>
                    <?php endif; ?>
                <?php endif; ?>

                <div class="row">
                    <!-- Check-in/Check-out Buttons -->
                    <div class="col-md-6 mb-4">
                        <div class="card h-100 border-0 shadow-sm">
                            <div class="card-header bg-primary text-white">
                                <i class="bi bi-door-open me-2"></i>Check In / Check Out
                            </div>
                            <div class="card-body d-flex flex-column justify-content-center align-items-center p-4">
                                <?php if (!$attendance || !$attendance['check_in']): ?>
                                    <!-- Not checked in yet -->
                                    <div class="text-center mb-3">
                                        <i class="bi bi-door-closed fs-1 text-muted"></i>
                                        <p class="mt-2">You haven't checked in today</p>
                                    </div>
                                    <form method="POST" action="" class="w-100">
                                        <input type="hidden" name="latitude" id="latitude">
                                        <input type="hidden" name="longitude" id="longitude">
                                        <button type="submit" name="check_in" id="check_in_btn" class="btn btn-primary btn-lg w-100" disabled>
                                            <i class="bi bi-box-arrow-in-right me-2"></i>Check In
                                        </button>

                                        <div id="location_status" class="mt-2 small text-center p-2">
                                            Click the button below to access your location
                                        </div>
                                        <div class="mt-2 text-center">
                                            <button type="button" id="request_location_btn" class="btn btn-info w-100">
                                                <i class="bi bi-geo-alt me-2"></i>Allow location access
                                            </button>
                                        </div>
                                        <div class="mt-3 small text-muted text-center">
                                            <i class="bi bi-info-circle-fill me-1"></i>
                                            If nothing happens when you click the button, check browser permissions
                                        </div>

                                        <!-- Direct script for location permission -->
                                        <script>
                                            document.addEventListener('DOMContentLoaded', function() {
                                                var locationBtn = document.getElementById('request_location_btn');
                                                var checkInBtn = document.getElementById('check_in_btn');
                                                var locationStatus = document.getElementById('location_status');
                                                var latField = document.getElementById('latitude');
                                                var longField = document.getElementById('longitude');

                                                // Check if we have stored coordinates from previous access in this session
                                                function checkSavedCoordinates() {
                                                    try {
                                                        var savedLat = sessionStorage.getItem('userLatitude');
                                                        var savedLng = sessionStorage.getItem('userLongitude');
                                                        var savedTime = sessionStorage.getItem('locationTimestamp');

                                                        // Check if coordinates exist and are not too old (less than 5 minutes)
                                                        if (savedLat && savedLng && savedTime) {
                                                            var now = new Date().getTime();
                                                            var timeDiff = now - parseInt(savedTime);

                                                            // If coordinates are less than 5 minutes old, use them
                                                            if (timeDiff < 5 * 60 * 1000) { // 5 minutes
                                                                console.log("Using saved coordinates");

                                                                // Update hidden fields
                                                                latField.value = savedLat;
                                                                longField.value = savedLng;

                                                                // Update UI
                                                                locationBtn.innerHTML = '<i class="bi bi-check-circle"></i> Location already granted';
                                                                locationBtn.className = 'btn btn-success w-100';
                                                                locationStatus.innerHTML = 'Saved location: ' +
                                                                    parseFloat(savedLat).toFixed(6) + ', ' +
                                                                    parseFloat(savedLng).toFixed(6);

                                                                // Enable check-in
                                                                checkInBtn.disabled = false;

                                                                return true;
                                                            }
                                                        }

                                                        return false;
                                                    } catch (e) {
                                                        console.error("Error checking saved coordinates:", e);
                                                        return false;
                                                    }
                                                }

                                                // First check if we have saved coordinates
                                                if (!checkSavedCoordinates()) {
                                                    console.log("No saved coordinates found");
                                                }

                                                if (locationBtn) {
                                                    console.log("Location button found and script loaded");

                                                    locationBtn.onclick = function() {
                                                        console.log("Location button clicked directly");

                                                        // Show loading
                                                        locationBtn.disabled = true;
                                                        locationBtn.innerHTML = 'Requesting location...';
                                                        locationStatus.innerHTML = 'Accessing location...';

                                                        // Simple direct request
                                                        if (navigator.geolocation) {
                                                            navigator.geolocation.getCurrentPosition(
                                                                function(position) {
                                                                    console.log("POSITION SUCCESS:", position.coords.latitude, position.coords.longitude);

                                                                    // Save to session storage
                                                                    try {
                                                                        sessionStorage.setItem('userLatitude', position.coords.latitude);
                                                                        sessionStorage.setItem('userLongitude', position.coords.longitude);
                                                                        sessionStorage.setItem('locationTimestamp', new Date().getTime());
                                                                        console.log("Coordinates saved to session storage");
                                                                    } catch (e) {
                                                                        console.error("Error saving to session storage:", e);
                                                                    }
                                                                    
                                                                    // Update hidden fields
                                                                    latField.value = position.coords.latitude;
                                                                    longField.value = position.coords.longitude;

                                                                    // Update UI
                                                                    locationBtn.innerHTML = '<i class="bi bi-check-circle"></i> Location access granted';
                                                                    locationBtn.className = 'btn btn-success w-100';
                                                                    locationStatus.innerHTML = 'Location detected: ' +
                                                                        position.coords.latitude.toFixed(6) + ', ' +
                                                                        position.coords.longitude.toFixed(6);

                                                                    // Enable check-in
                                                                    checkInBtn.disabled = false;
                                                                    locationBtn.disabled = false;
                                                                },
                                                                function(error) {
                                                                    console.error("POSITION ERROR:", error.code, error.message);

                                                                    // Reset button
                                                                    locationBtn.disabled = false;
                                                                    locationBtn.innerHTML = '<i class="bi bi-geo-alt me-2"></i>Try again';
                                                                    
                                                                    // Show detailed error message
                                                                    let errorMessage = '';
                                                                    switch(error.code) {
                                                                        case error.PERMISSION_DENIED:
                                                                            errorMessage = 'Location permission denied. Please enable location services in your browser settings and try again.';
                                                                            break;
                                                                        case error.POSITION_UNAVAILABLE:
                                                                            errorMessage = 'Location information is unavailable. Please try again.';
                                                                            break;
                                                                        case error.TIMEOUT:
                                                                            errorMessage = 'Location request timed out. Please try again.';
                                                                            break;
                                                                        default:
                                                                            errorMessage = 'Unknown error occurred: ' + error.message;
                                                                    }
                                                                    locationStatus.innerHTML = '<div class="text-danger"><i class="bi bi-exclamation-triangle-fill me-2"></i>' + errorMessage + '</div>';
                                                                },
                                                                {
                                                                    enableHighAccuracy: true,
                                                                    timeout: 10000,
                                                                    maximumAge: 0
                                                                }
                                                            );
                                                        } else {
                                                            alert("Geolocation not supported by your browser");
                                                            locationStatus.innerHTML = 'Error: Geolocation not supported';
                                                            locationBtn.disabled = false;
                                                        }

                                                        return false;
                                                    };
                                                } else {
                                                    console.error("Location button not found!");
                                                }
                                            });
                                        </script>
                                    </form>
                                <?php elseif ($attendance['check_in'] && !$attendance['check_out']): ?>
                                    <!-- Checked in but not checked out -->
                                    <div class="text-center mb-3">
                                        <i class="bi bi-door-open fs-1 text-success"></i>
                                        <p class="mt-2">You checked in at <?= date('h:i A', strtotime($attendance['check_in'])) ?></p>
                                    </div>
                                    <?php
                                    $checkoutDisabled = false;
                                    $disabledReason = "";

                                    // Check if worked hours are enough
                                    if ($attendance['check_in']) {
                                        // Get current server time from database
                                        $server_time_query = $conn->query("SELECT NOW() as server_time");
                                        $server_time_row = $server_time_query->fetch_assoc();
                                        $server_time = new DateTime($server_time_row['server_time']);

                                        // Calculate time difference using server time
                                        $check_in_time = new DateTime($attendance['check_in']);
                                        $time_diff = $server_time->diff($check_in_time);
                                        $hours_worked = ($time_diff->days * 24) + $time_diff->h + ($time_diff->i / 60);

                                        if ($hours_worked < 8) {
                                            $checkoutDisabled = true;
                                            $disabledReason = "Work at least 8 hours before checking out";
                                        }
                                    }
                                    ?>
                                    <form method="POST" action="" class="w-100">
                                        <button type="submit" name="check_out" class="btn btn-danger btn-lg w-100" <?= $checkoutDisabled ? 'disabled' : '' ?>>
                                            <i class="bi bi-box-arrow-right me-2"></i>Check Out
                                        </button>
                                        <?php if ($checkoutDisabled): ?>
                                            <small class="text-muted d-block mt-2 text-center"><?= $disabledReason ?></small>
                                        <?php endif; ?>
                                    </form>
                                <?php else: ?>
                                    <!-- Already checked out -->
                                    <div class="text-center mb-3">
                                        <i class="bi bi-check-circle fs-1 text-success"></i>
                                        <p class="mt-2">You checked out at <?= date('h:i A', strtotime($attendance['check_out'])) ?></p>
                                    </div>
                                    <div class="alert alert-success">
                                        You've completed your work day. Thank you!
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>

                    <!-- Break Buttons -->
                    <div class="col-md-6 mb-4">
                        <div class="card h-100 border-0 shadow-sm">
                            <div class="card-header bg-warning text-white">
                                <i class="bi bi-cup-hot me-2"></i>Break Management
                            </div>
                            <div class="card-body d-flex flex-column justify-content-center align-items-center p-4">
                                <?php if (!$attendance || !$attendance['check_in'] || $attendance['check_out']): ?>
                                    <!-- Not checked in or already checked out -->
                                    <div class="text-center mb-3">
                                        <i class="bi bi-cup me-2 fs-1 text-muted"></i>
                                        <p class="mt-2">You must check in first to use breaks</p>
                                    </div>
                                    <button class="btn btn-outline-warning btn-lg w-100" disabled>
                                        <i class="bi bi-cup-hot me-2"></i>Start Break
                                    </button>
                                <?php elseif ($attendance['check_in'] && !$attendance['check_out'] && !$attendance['break_start']): ?>
                                    <!-- Checked in and no active break -->
                                    <div class="text-center mb-3">
                                        <i class="bi bi-cup me-2 fs-1 text-warning"></i>
                                        <p class="mt-2">You can start a break now</p>
                                    </div>
                                    <?php
                                    // Check if 30 minutes have passed since check-in
                                    $check_in_time = new DateTime($attendance['check_in']);
                                    $server_time_query = $conn->query("SELECT NOW() as server_time");
                                    $server_time_row = $server_time_query->fetch_assoc();
                                    $server_time = new DateTime($server_time_row['server_time']);

                                    $time_diff = $server_time->diff($check_in_time);
                                    $minutes_worked = ($time_diff->days * 24 * 60) + ($time_diff->h * 60) + $time_diff->i;
                                    $break_disabled = $minutes_worked < 30;
                                    ?>

                                    <form method="POST" action="" class="w-100">
                                        <button type="submit" name="break_start" class="btn btn-warning btn-lg w-100" <?= $break_disabled ? 'disabled' : '' ?>>
                                            <i class="bi bi-cup-hot me-2"></i>Start Break
                                        </button>
                                        <?php if ($break_disabled): ?>
                                            <small class="text-muted d-block mt-2 text-center">
                                                Work at least 30 minutes before taking a break. Remaining: <?= 30 - $minutes_worked ?> minutes.
                                            </small>
                                        <?php endif; ?>
                                    </form>
                                <?php elseif ($attendance['check_in'] && !$attendance['check_out'] && $attendance['break_start'] && !$attendance['break_end']): ?>
                                    <!-- On active break -->
                                    <div class="text-center mb-3">
                                        <i class="bi bi-cup-hot-fill fs-1 text-warning"></i>
                                        <p class="mt-2">You're on a break since <?= date('h:i A', strtotime($attendance['break_start'])) ?></p>
                                    </div>
                                    <form method="POST" action="" class="w-100">
                                        <button type="submit" name="break_end" class="btn btn-success btn-lg w-100">
                                            <i class="bi bi-check-circle-fill me-2"></i>End Break
                                        </button>
                                    </form>
                                <?php elseif ($attendance['check_in'] && $attendance['break_start'] && $attendance['break_end']): ?>
                                    <!-- Break completed -->
                                    <div class="text-center mb-3">
                                        <i class="bi bi-check-circle fs-1 text-success"></i>
                                        <p class="mt-2">Last break completed</p>
                                    </div>
                                    <div class="alert alert-light text-center">
                                        <p>Break: <?= date('h:i A', strtotime($attendance['break_start'])) ?> - <?= date('h:i A', strtotime($attendance['break_end'])) ?></p>
                                        <p class="mb-0"><strong>Duration:</strong> <?= calculateBreakDuration($attendance['break_start'], $attendance['break_end']) ?></p>
                                    </div>
                                    <?php if (!$attendance['check_out']): ?>
                                        <form method="POST" action="" class="w-100 mt-3">
                                            <button type="submit" name="break_start" class="btn btn-warning btn-lg w-100">
                                                <i class="bi bi-cup-hot me-2"></i>Start New Break
                                            </button>
                                        </form>
                                    <?php endif; ?>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>


        <!-- Tasks Overview -->
        <div class="card mb-4">
            <div class="card-header bg-info text-white">
                <i class="bi bi-list-check me-2"></i>My Tasks
            </div>
            <div class="card-body">
                <?php if ($tasks_result && $tasks_result->num_rows > 0): ?>
                    <div class="row mb-3">
                        <div class="col-3 text-center">
                            <div class="fs-4 fw-bold text-primary"><?= $task_stats['total'] ?></div>
                            <div class="text-muted">Total</div>
                        </div>
                        <div class="col-3 text-center">
                            <div class="fs-4 fw-bold text-warning"><?= $task_stats['pending'] ?></div>
                            <div class="text-muted">Pending</div>
                        </div>
                        <div class="col-3 text-center">
                            <div class="fs-4 fw-bold text-success"><?= $task_stats['completed'] ?></div>
                            <div class="text-muted">Completed</div>
                        </div>
                        <div class="col-3 text-center">
                            <div class="fs-4 fw-bold text-danger"><?= $task_stats['overdue'] ?? 0 ?></div>
                            <div class="text-muted">Overdue</div>
                        </div>
                    </div>

                    <button type="button" class="btn btn-info w-100" data-bs-toggle="modal" data-bs-target="#tasksModal">
                        <i class="bi bi-eye me-1"></i> View My Tasks
                    </button>
                <?php else: ?>
                    <div class="text-center py-3">
                        <i class="bi bi-clipboard2-check fs-1 text-muted mb-3"></i>
                        <p>No tasks assigned yet.</p>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Timeline Table -->
        <div class="timeline-container">
            <h4><i class="bi bi-clock-history"></i>Today's Timeline</h4>
            <div class="timeline-scroll">
                <table class="timeline-table">
                    <thead>
                        <tr>
                            <th>Check In</th>
                            <th>Break Start</th>
                            <th>Break End</th>
                            <th>Break Duration</th>
                            <th>Check Out</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td class="<?= $attendance && $attendance['check_in'] ? 'highlight' : 'empty' ?>">
                                <?= $attendance && $attendance['check_in'] ? date('h:i A', strtotime($attendance['check_in'])) : '---' ?>
                            </td>
                            <td class="<?= $attendance && $attendance['break_start'] ? 'highlight' : 'empty' ?>">
                                <?= $attendance && $attendance['break_start'] ? date('h:i A', strtotime($attendance['break_start'])) : '---' ?>
                            </td>
                            <td class="<?= $attendance && $attendance['break_end'] ? 'highlight' : 'empty' ?>">
                                <?= $attendance && $attendance['break_end'] ? date('h:i A', strtotime($attendance['break_end'])) : '---' ?>
                            </td>
                            <td class="<?= ($attendance && $attendance['break_start'] && $attendance['break_end']) ? 'highlight' : 'empty' ?>">
                                <?= ($attendance && $attendance['break_start'] && $attendance['break_end']) ? calculateBreakDuration($attendance['break_start'], $attendance['break_end']) : '---' ?>
                            </td>
                            <td class="<?= $attendance && $attendance['check_out'] ? 'highlight' : 'empty' ?>">
                                <?= $attendance && $attendance['check_out'] ? date('h:i A', strtotime($attendance['check_out'])) : '---' ?>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Tasks Modal -->
    <div class="modal fade" id="tasksModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header bg-info text-white">
                    <h5 class="modal-title"><i class="bi bi-list-check me-2"></i>My Tasks</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <?php
                    // Reset the result pointer to the beginning
                    if ($tasks_result) {
                        $tasks_result->data_seek(0);
                    }

                    if ($tasks_result && $tasks_result->num_rows > 0):
                    ?>
                        <div class="list-group">
                            <?php while ($task = $tasks_result->fetch_assoc()): ?>
                                <div class="list-group-item list-group-item-action p-3 <?= $task['status'] === 'completed' ? 'bg-light' : '' ?>">
                                    <div class="d-flex justify-content-between align-items-center mb-2">
                                        <h5 class="mb-0 <?= $task['status'] === 'completed' ? 'text-decoration-line-through text-muted' : '' ?>">
                                            <?= htmlspecialchars($task['task_description']) ?>
                                        </h5>
                                        <div>
                                            <?php
                                            switch ($task['status']) {
                                                case 'pending':
                                                    echo '<span class="badge bg-warning">Pending</span>';
                                                    break;
                                                case 'completed':
                                                    echo '<span class="badge bg-success">Completed</span>';
                                                    break;
                                                case 'in_progress':
                                                    echo '<span class="badge bg-info">In Progress</span>';
                                                    break;
                                            }
                                            ?>
                                            <span class="badge bg-<?=
                                                                    $task['priority'] === 'high' ? 'danger' : ($task['priority'] === 'medium' ? 'warning' : 'info')
                                                                    ?>">
                                                <?= ucfirst($task['priority']) ?>
                                            </span>
                                        </div>
                                    </div>

                                    <?php if ($task['due_date']): ?>
                                        <div class="mb-2">
                                            <?php
                                            $due_date = new DateTime($task['due_date']);
                                            $today = new DateTime();
                                            $is_overdue = $due_date < $today && $task['status'] !== 'completed';
                                            ?>

                                            <?php if ($is_overdue): ?>
                                                <span class="text-danger">
                                                    <i class="bi bi-exclamation-triangle-fill"></i>
                                                    Overdue: Due <?= $due_date->format('M j, Y') ?>
                                                </span>
                                            <?php else: ?>
                                                <strong>Due:</strong> <?= $due_date->format('M j, Y') ?>
                                            <?php endif; ?>
                                        </div>
                                    <?php endif; ?>

                                    <?php if ($task['notes']): ?>
                                        <div class="small text-muted mb-2">
                                            <?= htmlspecialchars($task['notes']) ?>
                                        </div>
                                    <?php endif; ?>

                                    <div class="d-flex justify-content-between align-items-center mt-2">
                                        <small class="text-muted">
                                            Assigned: <?= date('M j', strtotime($task['created_at'])) ?>
                                            <?php if ($task['completed_at']): ?>
                                                | Completed: <?= date('M j', strtotime($task['completed_at'])) ?>
                                            <?php endif; ?>
                                        </small>

                                        <a href="employee_tasks.php#updateTaskModal<?= $task['id'] ?>" class="btn btn-sm btn-outline-primary">
                                            Update
                                        </a>
                                    </div>
                                </div>
                            <?php endwhile; ?>
                        </div>

                        <div class="text-center mt-3">
                            <a href="employee_tasks.php" class="btn btn-primary">
                                <i class="bi bi-list-check me-1"></i> Manage All Tasks
                            </a>
                        </div>
                    <?php else: ?>
                        <div class="text-center p-4">
                            <i class="bi bi-clipboard2-check display-4 text-muted mb-3"></i>
                            <p>No tasks assigned yet.</p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Auto-dismiss alerts after 5 seconds
        document.addEventListener('DOMContentLoaded', function() {
            // Get location for check-in
            const checkInBtn = document.getElementById('check_in_btn');
            const locationStatus = document.getElementById('location_status');
            const latitudeField = document.getElementById('latitude');
            const longitudeField = document.getElementById('longitude');

            // Enhanced function to get current location with better mobile support
            function getLocation() {
                // Update status first with loading indicator
                locationStatus.innerHTML = '<div class="d-flex align-items-center"><span class="spinner-border spinner-border-sm me-2"></span> Determining your location...</div>';

                // Check if geolocation is supported
                if (!navigator.geolocation) {
                    locationStatus.innerHTML = "<i class='bi bi-x-circle-fill text-danger'></i> Your browser does not support location services";
                    return;
                }

                // Better mobile device detection
                const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
                const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent);
                const isAndroid = /Android/.test(navigator.userAgent);

                console.log("Device detection:", {
                    isMobile: isMobile,
                    isIOS: isIOS,
                    isAndroid: isAndroid,
                    userAgent: navigator.userAgent
                });

                // Advanced options for different device types
                const geoOptions = {
                    // On mobile, we'll first try without high accuracy to get faster results
                    // On iOS, high accuracy mode tends to work better
                    enableHighAccuracy: isIOS ? true : !isMobile,
                    // Extended timeout for mobile devices
                    timeout: isMobile ? 30000 : 15000,
                    // Don't use cached position for attendance tracking
                    maximumAge: 0
                };

                console.log("Requesting location with options:", JSON.stringify(geoOptions));
                console.log("Device type:", isMobile ? (isIOS ? "iOS Mobile" : (isAndroid ? "Android" : "Other Mobile")) : "Desktop");

                // Variable to track retry attempts with different settings
                let retryWithHighAccuracy = false;

                // Function to log diagnostic information to server for debugging
                const logLocationDiagnostics = function(type, data) {
                    try {
                        // Create a diagnostic payload
                        const diagnosticData = {
                            timestamp: new Date().toISOString(),
                            type: type,
                            userAgent: navigator.userAgent,
                            deviceType: isMobile ? (isIOS ? "iOS" : (isAndroid ? "Android" : "Other Mobile")) : "Desktop",
                            data: data
                        };

                        // Send diagnostic data to server (non-blocking)
                        const logRequest = new XMLHttpRequest();
                        logRequest.open('POST', 'log_diagnostics.php', true);
                        logRequest.setRequestHeader('Content-Type', 'application/json');
                        logRequest.send(JSON.stringify(diagnosticData));

                        console.log("Diagnostic log sent:", type, diagnosticData);
                    } catch (err) {
                        console.error("Error logging diagnostics:", err);
                    }
                };

                // Function to handle location success
                const handleLocationSuccess = function(position) {
                    try {
                        console.log("Raw position data:", JSON.stringify({
                            latitude: position.coords.latitude,
                            longitude: position.coords.longitude,
                            accuracy: position.coords.accuracy,
                            timestamp: position.timestamp,
                            highAccuracy: geoOptions.enableHighAccuracy
                        }));

                        // Log successful location for diagnostics
                        logLocationDiagnostics('location_success', {
                            latitude: position.coords.latitude,
                            longitude: position.coords.longitude,
                            accuracy: position.coords.accuracy,
                            timestamp: position.timestamp,
                            highAccuracy: geoOptions.enableHighAccuracy,
                            altitude: position.coords.altitude,
                            altitudeAccuracy: position.coords.altitudeAccuracy,
                            heading: position.coords.heading,
                            speed: position.coords.speed
                        });

                        // Store in form fields
                        latitudeField.value = position.coords.latitude;
                        longitudeField.value = position.coords.longitude;

                        // Enable check-in button
                        checkInBtn.disabled = false;

                        // Show success message with accuracy information
                        const accuracyMeters = Math.round(position.coords.accuracy || 0);
                        const accuracyClass = accuracyMeters <= 100 ? "text-success" : (accuracyMeters <= 500 ? "text-warning" : "text-danger");

                        locationStatus.innerHTML = `
                            <div class="text-success"><i class="bi bi-geo-alt-fill me-1"></i> Location determined successfully</div>
                            <div class="small ${accuracyClass}">Accuracy: ${accuracyMeters} meters</div>
                            <div class="small text-muted mt-1">
                                ${geoOptions.enableHighAccuracy ? 
                                    '<i class="bi bi-check-circle-fill text-success me-1"></i> High accuracy used' : 
                                    '<i class="bi bi-info-circle me-1"></i> Normal accuracy used'}
                            </div>
                        `;

                        console.log("Location successfully obtained and processed");
                    } catch (err) {
                        console.error("Error processing location data:", err);
                        locationStatus.innerHTML = "<i class='bi bi-exclamation-circle-fill text-warning'></i> An error occurred while processing location data";
                    }
                };

                // Function to handle location errors with retry logic
                const handleLocationError = function(error) {
                    console.error("Geolocation error code:", error.code, "Message:", error.message, "Using high accuracy:", geoOptions.enableHighAccuracy);

                    // Log error for diagnostics
                    logLocationDiagnostics('location_error', {
                        code: error.code,
                        message: error.message,
                        highAccuracy: geoOptions.enableHighAccuracy
                    });

                    // Provide user-friendly error messages
                    let errorMessage = '';
                    let troubleshooting = '';
                    
                    switch(error.code) {
                        case error.PERMISSION_DENIED:
                            errorMessage = 'Please enable location services and refresh the page.';
                            troubleshooting = `
                                <ol class="small">
                                    <li>Enable location services in your device settings</li>
                                    <li>Refresh the page and try again</li>
                                </ol>
                            `;
                            break;
                        case error.POSITION_UNAVAILABLE:
                            errorMessage = 'Location information is unavailable. Please try again.';
                            troubleshooting = `
                                <ol class="small">
                                    <li>Make sure you have a stable internet connection</li>
                                    <li>Try again in a few moments</li>
                                </ol>
                            `;
                            break;
                        case error.TIMEOUT:
                            errorMessage = 'Location request timed out. Please try again.';
                            troubleshooting = `
                                <ol class="small">
                                    <li>Check your internet connection</li>
                                    <li>Try again in a few moments</li>
                                </ol>
                            `;
                            break;
                        default:
                            errorMessage = 'Unable to get location. Please try again.';
                            troubleshooting = `
                                <ol class="small">
                                    <li>Refresh the page</li>
                                    <li>Try again in a few moments</li>
                                </ol>
                            `;
                    }

                    // Update UI with error message and troubleshooting
                    locationStatus.innerHTML = `
                        <div class="alert alert-danger">
                            <h6 class="alert-heading mb-2"><i class="bi bi-exclamation-triangle-fill me-2"></i>Location Error</h6>
                            <p class="mb-2">${errorMessage}</p>
                            <div class="small mb-2">${troubleshooting}</div>
                            <p class="small mb-0">
                                <button type="button" class="btn btn-sm btn-primary" onclick="getLocation()">
                                    <i class="bi bi-arrow-clockwise me-2"></i>Try Again
                                </button>
                            </p>
                        </div>
                    `;

                    // For mobile devices, if first attempt fails without high accuracy, try once with high accuracy
                    if (isMobile && !geoOptions.enableHighAccuracy && !retryWithHighAccuracy) {
                        console.log("Retrying with high accuracy enabled");
                        retryWithHighAccuracy = true;

                        locationStatus.innerHTML = '<div class="d-flex align-items-center"><span class="spinner-border spinner-border-sm me-2"></span> جاري المحاولة بدقة أعلى...</div>';

                        // Log retry attempt
                        logLocationDiagnostics('location_retry', {
                            originalError: {
                                code: error.code,
                                message: error.message
                            },
                            newSettings: {
                                enableHighAccuracy: true,
                                timeout: 30000,
                                maximumAge: 0
                            }
                        });

                        // Try again with high accuracy
                        navigator.geolocation.getCurrentPosition(
                            handleLocationSuccess,
                            function(retryError) {
                                // If retry also fails, show detailed error
                                console.error("Retry with high accuracy failed:", retryError.code, retryError.message);
                                showDetailedError(retryError);
                            }, {
                                enableHighAccuracy: true,
                                timeout: 30000,
                                maximumAge: 0
                            }
                        );
                        return;
                    }

                    // If we get here, show the detailed error
                    showDetailedError(error);
                };

                // Function to show detailed error messages
                const showDetailedError = function(error) {
                    let errorTitle = "";
                    let errorMsg = "";
                    let troubleshooting = "";

                    // Prepare error details based on error code
                    switch (error.code) {
                        case error.PERMISSION_DENIED:
                            errorTitle = "Access to your location was denied";
                            errorMsg = "The browser did not allow access to your geographical location";
                            troubleshooting = `
                                <div class="alert alert-warning small mt-2 mb-0 px-2 py-2">
                                    <strong>To fix the problem:</strong>
                                    <ul class="ps-3 mb-0 mt-1">
                                        ${isIOS ? `
                                            <li>Open your device settings (Settings)</li>
                                            <li>Navigate to Privacy then Location Services</li>
                                            <li>Ensure location services are enabled</li>
                                            <li>Find your browser (Safari or Chrome) and select "During app usage"</li>
                                        ` : ''}
                                        
                                        ${isAndroid ? `
                                            <li>Open your device settings</li>
                                            <li>Navigate to Permissions/Privacy</li>
                                            <li>Select "Location"</li>
                                            <li>Ensure you enable the permission for the browser you are using</li>
                                        ` : ''}
                                        
                                        <li>In the browser window, click the lock/location icon in the address bar</li>
                                        <li>Ensure you select "Allow" to access your location</li>
                                        <li>Ensure location services are enabled in your device settings</li>
                                        <li>Try reloading the page</li>
                                    </ul>
                                </div>
                            `;
                            break;

                        case error.POSITION_UNAVAILABLE:
                            errorTitle = "Unable to access your location";
                            errorMsg = "The device cannot determine your current location";
                            troubleshooting = `
                                <div class="alert alert-warning small mt-2 mb-0 px-2 py-2">
                                    <strong>To fix the problem:</strong>
                                    <ul class="ps-3 mb-0 mt-1">
                                        <li>Check if GPS is enabled on your device</li>
                                        <li>Ensure you have a strong internet connection</li>
                                        <li>Go to an open area or near a window</li>
                                        <li>Close other applications that might be using location services</li>
                                        <li>Restart the device and try again</li>
                                    </ul>
                                </div>
                            `;
                            break;

                        case error.TIMEOUT:
                            errorTitle = "The location request timed out";
                            errorMsg = "It took too long to determine your location";
                            troubleshooting = `
                                <div class="alert alert-warning small mt-2 mb-0 px-2 py-2">
                                    <strong>To fix the problem:</strong>
                                    <ul class="ps-3 mb-0 mt-1">
                                        <li>Check if you have a strong mobile signal</li>
                                        <li>Ensure GPS is enabled and connected to satellite networks</li>
                                        <li>Go to an open area away from tall buildings</li>
                                        <li>Try running in low power mode (may affect GPS accuracy)</li>
                                        <li>Try using a different browser (Chrome or Firefox)</li>
                                    </ul>
                                </div>
                            `;
                            break;

                        default:
                            errorTitle = "Unknown error";
                            errorMsg = "An unexpected error occurred while determining your location";
                            troubleshooting = `
                                <div class="alert alert-warning small mt-2 mb-0 px-2 py-2">
                                    <strong>To fix the problem:</strong>
                                    <ul class="ps-3 mb-0 mt-1">
                                        <li>Reload the page</li>
                                        <li>Try using a different browser</li>
                                        <li>Ensure the operating system and browser are up to date</li>
                                        <li>Clear the browser's cache</li>
                                        <li>Check the location permissions in device settings</li>
                                    </ul>
                                </div>
                            `;
                            break;
                    }

                    // Update the UI with detailed error information
                    locationStatus.innerHTML = `
                        <div class="text-danger fw-bold mb-1"><i class="bi bi-exclamation-triangle-fill me-2"></i>${errorTitle}</div>
                        <div class="mb-2">${errorMsg}</div>
                        ${troubleshooting}
                        <button id="retry_location_btn" class="btn btn-sm btn-primary mt-2 w-100">
                            <i class="bi bi-arrow-repeat me-1"></i> Try again
                        </button>
                    `;

                    // Add event listener to retry button
                    setTimeout(() => {
                        const retryBtn = document.getElementById('retry_location_btn');
                        if (retryBtn) {
                            retryBtn.addEventListener('click', getLocation);
                        }
                    }, 100);
                };

                // Try to get current position with enhanced error handling
                navigator.geolocation.getCurrentPosition(
                    handleLocationSuccess,
                    handleLocationError,
                    geoOptions
                );
            } else {
                // Detailed message for browsers that don't support geolocation
                locationStatus.innerHTML = `
                    <div class="alert alert-danger p-3">
                        <h6 class="mb-2"><i class="bi bi-x-circle-fill me-2"></i>Your browser does not support location services</h6>
                        <p class="mb-2 small">Please use a modern browser that supports location services (GPS) like:</p>
                        <ul class="small mb-0 ps-3">
                            <li>Google Chrome (latest)</li>
                            <li>Safari (latest)</li>
                            <li>Firefox (latest)</li>
                            <li>Samsung Internet (latest)</li>
                        </ul>
                    </div>
                    <div class="mt-3 text-center">
                        <div class="d-grid">
                            <button onclick="window.location.reload()" class="btn btn-outline-secondary btn-sm">
                                <i class="bi bi-arrow-clockwise me-1"></i> Reload page
                            </button>
                        </div>
                        <div class="mt-2 small text-muted">
                            If the problem persists, please request assistance from the system manager
                        </div>
                    </div>
                `;

                // Log error for debugging
                console.error("Geolocation API is not supported by this browser");

                // Manually enable button if needed for testing
                // Uncomment the following line to enable the check-in button even without location
                // checkInBtn.disabled = false;
            }

            // Configure location buttons when checkInBtn exists
            if (checkInBtn) {
                const requestLocationBtn = document.getElementById('request_location_btn');

                // Set up the request location button
                if (requestLocationBtn) {
                    console.log("Location request button found", requestLocationBtn);
                    requestLocationBtn.addEventListener('click', function(e) {
                                    <div class="small text-muted">Accuracy: ${accuracyMeters} meters</div>
                                `;
                            },
                            // Error callback
                            function(error) {
                                console.error("Geolocation error:", error.code, error.message);
                                alert("Error accessing location. Error code: " + error.code);

                                // Reset button
                                requestLocationBtn.disabled = false;
                                requestLocationBtn.innerHTML = '<i class="bi bi-geo-alt me-2"></i>Retry location access';

                                // Show error
                                locationStatus.innerHTML = `
                                    <div class="text-danger"><i class="bi bi-exclamation-triangle-fill me-1"></i>Location error (${error.code})</div>
                                    <div class="small">${error.message}</div>
                                `;
                            }, {
                                enableHighAccuracy: true,
                                timeout: 30000,
                                maximumAge: 0
                            }
                        );
                    });

                    // Highlight the button to attract attention
                    setTimeout(() => {
                        requestLocationBtn.classList.add('btn-pulse');
                    }, 500);
                } else {
                    console.error("Location request button not found");
                }

                // Add refresh button
                const refreshDiv = document.createElement('div');
                refreshDiv.className = 'mt-3 border-top pt-3';
                refreshDiv.innerHTML = `
                    <div class="d-grid">
                        <button type='button' class='btn btn-primary'>
                            <i class='bi bi-geo-alt-fill me-2'></i>
                            <span>Update my geographical location</span>
                        </button>
                    </div>
                    <div class="text-center mt-2 small text-muted">
                        If you encounter any problems determining your location, click here to try again
                    </div>
                `;

                locationStatus.parentNode.appendChild(refreshDiv);

                // Add event listener to refresh button
                const refreshButton = refreshDiv.querySelector('button');
                if (refreshButton) {
                    refreshButton.addEventListener('click', function() {
                        // Show loading state
                        const originalHTML = this.innerHTML;
                        this.disabled = true;
                        this.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>جاري تحديد الموقع...';

                        // Attempt to get location
                        getLocation();

                        // Reset button after delay
                        setTimeout(() => {
                            this.disabled = false;
                            this.innerHTML = originalHTML;
                        }, 3000);
                    });
                }
            }

            // Auto-dismiss alerts
            const alerts = document.querySelectorAll('.alert');
            alerts.forEach(alert => {
                setTimeout(() => {
                    const closeBtn = alert.querySelector('.btn-close');
                    if (closeBtn) {
                        closeBtn.click();
                    }
                }, 5000);
            });

            // Break duration timer
            const breakDurationEl = document.getElementById('currentBreakDuration');
            const breakRemainingEl = document.getElementById('breakRemainingTime');

            if (breakDurationEl) {
                // Get server timestamp and break start time
                <?php if ($attendance && $attendance['break_start'] && !$attendance['break_end']): ?>
                    const breakStartTime = '<?= $attendance['break_start'] ?>';

                    // Get the server-client time difference to maintain accuracy
                    const serverTime = new Date('<?= $server_time_row['server_time'] ?>');
                    const clientTime = new Date();
                    const timeOffset = serverTime - clientTime;

                    // Initial values from server with fallbacks to prevent NaN
                    let durationMinutes = parseInt('<?= intval($break_minutes) ?>') || 0;
                    let durationSeconds = parseInt('<?= intval($break_seconds) ?>') || 0;

                    // Update the break duration timer every second
                    setInterval(() => {
                        try {
                            // Increment the seconds
                            durationSeconds++;

                            // Handle minute rollover
                            if (durationSeconds >= 60) {
                                durationSeconds = 0;
                                durationMinutes++;
                            }

                            // Update the display with error handling
                            if (isNaN(durationMinutes) || isNaN(durationSeconds)) {
                                // Reset to prevent NaN display
                                durationMinutes = 0;
                                durationSeconds = 0;
                            }

                            // Update the display with padded values
                            breakDurationEl.textContent = `${String(durationMinutes).padStart(2, '0')}:${String(durationSeconds).padStart(2, '0')}`;
                        } catch (error) {
                            console.error("Error updating break duration timer:", error);
                            breakDurationEl.textContent = "00:00"; // Fallback display
                        }
                    }, 1000);

                    <?php if ($scheduled_end_time): ?>
                        // For the remaining time countdown with fallbacks to prevent NaN
                        let remainingMinutes = parseInt('<?= $remaining_negative ? "-" . $remaining_minutes : $remaining_minutes ?>') || 0;
                        let remainingSeconds = parseInt('<?= $remaining_negative ? "-" . $remaining_seconds : $remaining_seconds ?>') || 0;
                        const isNegative = <?= $remaining_negative ? 'true' : 'false' ?>;

                        // Update the remaining time every second
                        setInterval(() => {
                            try {
                                if (isNaN(remainingMinutes) || isNaN(remainingSeconds)) {
                                    // Reset to prevent NaN display
                                    remainingMinutes = 0;
                                    remainingSeconds = 0;
                                }

                                if (isNegative) {
                                    // Count up if already exceeded
                                    remainingSeconds++;
                                    if (remainingSeconds >= 60) {
                                        remainingSeconds = 0;
                                        remainingMinutes++;
                                    }
                                    breakRemainingEl.textContent = `Break time exceeded by ${String(Math.abs(remainingMinutes)).padStart(2, '0')}:${String(Math.abs(remainingSeconds)).padStart(2, '0')}`;
                                    breakRemainingEl.className = 'badge bg-danger p-2';
                                } else {
                                    // Count down if time remaining
                                    remainingSeconds--;
                                    if (remainingSeconds < 0) {
                                        remainingSeconds = 59;
                                        remainingMinutes--;
                                    }

                                    // Check if the time is up
                                    if (remainingMinutes <= 0 && remainingSeconds <= 0) {
                                        remainingMinutes = 0;
                                        remainingSeconds = 0;
                                        breakRemainingEl.textContent = `Break time exceeded`;
                                        breakRemainingEl.className = 'badge bg-danger p-2';

                                        // Add notification
                                        if ('Notification' in window && Notification.permission === 'granted') {
                                            try {
                                                new Notification('Break Time Ended', {
                                                    body: 'Your break time has ended. Please return to work.',
                                                    icon: '/favicon.ico'
                                                });
                                            } catch (e) {
                                                console.error('Notification error:', e);
                                            }
                                        }

                                        // Play sound alert
                                        try {
                                            const audio = new Audio('/assets/alert.mp3');
                                            audio.play().catch(e => console.log('Sound play error:', e));
                                        } catch (e) {
                                            console.error('Audio play error:', e);
                                        }

                                        // Automatically end the break
                                        fetch('auto_end_break.php', {
                                            method: 'POST',
                                            headers: {
                                                'Content-Type': 'application/json',
                                            },
                                            body: JSON.stringify({
                                                employee_id: <?= $employee_id ?>,
                                                date: '<?= $today ?>'
                                            })
                                        })
                                        .then(response => response.json())
                                        .then(data => {
                                            if (data.success) {
                                                // Reload the page to reflect the changes
                                                window.location.reload();
                                            } else {
                                                console.error('Failed to auto-end break:', data.error);
                                            }
                                        })
                                        .catch(error => {
                                            console.error('Error auto-ending break:', error);
                                        });

                                        // Change to negative counting up
                                        setTimeout(() => {
                                            remainingMinutes = 0;
                                            remainingSeconds = 1;
                                            isNegative = true;
                                        }, 1000);
                                    } else {
                                        breakRemainingEl.textContent = `${String(remainingMinutes).padStart(2, '0')}:${String(remainingSeconds).padStart(2, '0')} remaining`;
                                    }
                                }
                            } catch (error) {
                                console.error("Error updating remaining time:", error);
                                breakRemainingEl.textContent = "00:00 remaining"; // Fallback display
                            }
                        }, 1000);
                    <?php endif; ?>
                <?php endif; ?>
            }

            // Update the status card break timer as well if it exists
            const statusCardBreakCounter = document.getElementById('statusCardBreakCounter');
            if (statusCardBreakCounter) {
                try {
                    // Get attributes with fallbacks to prevent NaN
                    const isNegative = statusCardBreakCounter.getAttribute('data-negative') === 'true';
                    let statusMinutes = parseInt(statusCardBreakCounter.getAttribute('data-minutes')) || 0;
                    let statusSeconds = parseInt(statusCardBreakCounter.getAttribute('data-seconds')) || 0;

                    // Initialize with valid values
                    if (isNaN(statusMinutes)) statusMinutes = 0;
                    if (isNaN(statusSeconds)) statusSeconds = 0;

                    // Display initial values first to prevent flashing NaN
                    if (isNegative) {
                        statusCardBreakCounter.textContent = `Break time exceeded by ${statusMinutes}m ${statusSeconds}s`;
                    } else {
                        statusCardBreakCounter.textContent = `${statusMinutes} minutes ${statusSeconds} seconds remaining`;
                    }

                    setInterval(() => {
                        try {
                            if (isNegative) {
                                // Count up if already exceeded
                                statusSeconds++;
                                if (statusSeconds >= 60) {
                                    statusSeconds = 0;
                                    statusMinutes++;
                                }
                                statusCardBreakCounter.textContent = `Break time exceeded by ${statusMinutes}m ${statusSeconds}s`;
                            } else {
                                // Count down
                                statusSeconds--;
                                if (statusSeconds < 0) {
                                    statusSeconds = 59;
                                    statusMinutes--;
                                }

                                if (statusMinutes <= 0 && statusSeconds <= 0) {
                                    statusCardBreakCounter.textContent = 'Break time exceeded';
                                    let parentDiv = statusCardBreakCounter.parentElement.querySelector('div:first-child');
                                    if (parentDiv) {
                                        parentDiv.innerHTML = '<i class="bi bi-hourglass-split me-1"></i> Break Time Exceeded';
                                    }
                                    // Change to negative counting
                                    setTimeout(() => {
                                        statusMinutes = 0;
                                        statusSeconds = 1;
                                        statusCardBreakCounter.setAttribute('data-negative', 'true');
                                    }, 1000);
                                } else {
                                    statusCardBreakCounter.textContent = `${statusMinutes} minutes ${statusSeconds} seconds remaining`;
                                }
                            }
                        } catch (error) {
                            console.error("Error updating status card break timer:", error);
                            statusCardBreakCounter.textContent = "00:00"; // Fallback display
                        }
                    }, 1000);
                } catch (error) {
                    console.error("Error initializing status card break timer:", error);
                    if (statusCardBreakCounter) {
                        statusCardBreakCounter.textContent = "00:00"; // Fallback display
                    }
                }
            }

            // Request notification permission if supported
            if ('Notification' in window && Notification.permission !== 'granted' && Notification.permission !== 'denied') {
                // Request permission
                Notification.requestPermission();
            }
        });
    </script>

    <!-- Theme Modal -->
    <div class="modal fade" id="themeModal" tabindex="-1" aria-labelledby="themeModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="themeModalLabel"><i class="bi bi-palette-fill me-2"></i>Change Theme</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <p>Choose your preferred theme color. This theme will be applied to all employee pages.</p>

                    <form method="POST" action="">
                        <div class="d-flex gap-3 mb-3">
                            <div class="form-check">
                                <input class="form-check-input" type="radio" name="theme" id="theme_purple" value="purple" <?= $theme_color === 'purple' ? 'checked' : '' ?>>
                                <label class="form-check-label" for="theme_purple">
                                    <span class="badge" style="background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%); width: 80px; height: 30px;"></span>
                                    Purple/Blue Theme
                                </label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="radio" name="theme" id="theme_red" value="red" <?= $theme_color === 'red' ? 'checked' : '' ?>>
                                <label class="form-check-label" for="theme_red">
                                    <span class="badge" style="background: linear-gradient(135deg, #cb1111 0%, #fc2525 100%); width: 80px; height: 30px;"></span>
                                    Red Theme
                                </label>
                            </div>
                        </div>

                        <div class="d-grid mt-4">
                            <button type="submit" name="change_theme" class="btn btn-primary">
                                <i class="bi bi-check-circle me-1"></i> Apply Theme
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
</body>

</html>