<?php
session_name('admin_session'); // Give admin session a unique name
session_start();
require 'db.php';
require 'theme_helper.php'; // Include theme helper

// Get the admin theme color
$theme_color = getAdminThemeColor($conn);

if (!isset($_SESSION['is_admin']) || !isset($_SESSION['admin_cookie'])) {
    header("Location: admin_login.php");
    exit;
}

// Check for employee ID
$employee_id = isset($_GET['id']) ? intval($_GET['id']) : 0;

if ($employee_id <= 0) {
    header("Location: admin.php?error=invalid_employee");
    exit;
}

// Ensure database connection
$conn = ensureConnection($conn);
if (!$conn) {
    header("Location: admin.php?error=db_connection");
    exit;
}

// Get employee data
$stmt = $conn->prepare("SELECT * FROM employees WHERE id = ?");
$stmt->bind_param("i", $employee_id);
$stmt->execute();
$result = $stmt->get_result();
$employee = $result->fetch_assoc();

if (!$employee) {
    header("Location: admin.php?error=employee_not_found");
    exit;
}

// Handle actions
$message = '';
$error = '';

// Handle break start
if (isset($_POST['add_break'])) {
    $break_minutes = isset($_POST['break_minutes']) ? intval($_POST['break_minutes']) : 15;
    $break_type = isset($_POST['break_type']) ? $_POST['break_type'] : 'lunch';
    
    // Validate break minutes (minimum 5, maximum 60)
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
        $stmt = $conn->prepare("
            UPDATE attendance 
            SET break_start = ?, break_end = NULL 
            WHERE employee_id = ? 
            AND date = CURRENT_DATE 
            AND check_in IS NOT NULL 
            AND check_out IS NULL
            AND (break_start IS NULL OR (break_start IS NOT NULL AND break_end IS NOT NULL))
        ");
        $stmt->bind_param("si", $break_start, $employee_id);
        
        if ($stmt->execute() && $stmt->affected_rows > 0) {
            // Insert into break_schedule table
            $stmt = $conn->prepare("
                INSERT INTO break_schedule (employee_id, break_start, scheduled_end, created_at, break_type)
                VALUES (?, ?, ?, NOW(), ?)
            ");
            $stmt->bind_param("isss", $employee_id, $break_start, $break_end, $break_type);
            $stmt->execute();
            
            // Add record to admin_alerts table for tracking
            $alert_message = ucfirst($break_type) . " break started for " . $employee['name'] . " (" . $break_minutes . " minutes)";
            $alert_stmt = $conn->prepare("
                INSERT INTO admin_alerts (employee_id, message, device_info, is_read) 
                VALUES (?, ?, 'Admin action from break management page', 0)
            ");
            $alert_stmt->bind_param("is", $employee_id, $alert_message);
            $alert_stmt->execute();
            
            $conn->commit();
            $message = ucfirst($break_type) . " break started successfully for {$break_minutes} minutes";
        } else {
            throw new Exception("Cannot start break. Employee might be on break or not checked in.");
        }
    } catch (Exception $e) {
        $conn->rollback();
        $error = "Error starting break: " . $e->getMessage();
    }
}

// Handle break end
if (isset($_POST['end_break'])) {
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
        $break_stmt->bind_param("i", $employee_id);
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
        $stmt->bind_param("i", $employee_id);
        
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
            $update_stmt->bind_param("i", $employee_id);
            $update_stmt->execute();
            
            // Calculate break duration if we have the details
            if ($break_details) {
                $break_type = ucfirst($break_details['break_type'] ?? 'break');
                $break_start = new DateTime($break_details['break_start']);
                $duration_mins = ceil(($end_time->getTimestamp() - $break_start->getTimestamp()) / 60);
                
                // Add record to admin_alerts table for tracking
                $alert_message = "$break_type break ended for employee #$employee_id (duration: $duration_mins minutes)";
                $alert_stmt = $conn->prepare("
                    INSERT INTO admin_alerts (employee_id, message, device_info, is_read) 
                    VALUES (?, ?, 'Admin action from break management page', 0)
                ");
                $alert_stmt->bind_param("is", $employee_id, $alert_message);
                $alert_stmt->execute();
                
                $message = "$break_type break ended successfully after $duration_mins minutes";
            } else {
                $message = "Break ended successfully";
            }
            
            $conn->commit();
        } else {
            throw new Exception("Cannot end break. Employee might not be on break.");
        }
    } catch (Exception $e) {
        $conn->rollback();
        $error = "Error ending break: " . $e->getMessage();
    }
}

// Get today's attendance
$today = date('Y-m-d');
$attendance_stmt = $conn->prepare("SELECT * FROM attendance WHERE employee_id = ? AND date = ?");
$attendance_stmt->bind_param("is", $employee_id, $today);
$attendance_stmt->execute();
$attendance = $attendance_stmt->get_result()->fetch_assoc();

// Get break history for this employee
$history_stmt = $conn->prepare("
    SELECT 
        bs.id,
        bs.break_start,
        bs.scheduled_end,
        bs.actual_end,
        COALESCE(bs.break_type, 'lunch') AS break_type,
        TIMESTAMPDIFF(MINUTE, bs.break_start, COALESCE(bs.actual_end, NOW())) AS duration_minutes
    FROM 
        break_schedule bs
    WHERE 
        bs.employee_id = ?
    ORDER BY 
        bs.break_start DESC
    LIMIT 20
");
$history_stmt->bind_param("i", $employee_id);
$history_stmt->execute();
$break_history = $history_stmt->get_result();

// Get break statistics for this employee
$stats_stmt = $conn->prepare("
    SELECT 
        COUNT(*) AS total_breaks,
        SUM(CASE WHEN COALESCE(break_type, 'lunch') = 'lunch' THEN 1 ELSE 0 END) AS lunch_breaks,
        SUM(CASE WHEN COALESCE(break_type, 'lunch') = 'rest' THEN 1 ELSE 0 END) AS rest_breaks,
        SUM(TIMESTAMPDIFF(MINUTE, break_start, COALESCE(actual_end, NOW()))) AS total_minutes,
        AVG(TIMESTAMPDIFF(MINUTE, break_start, actual_end)) AS avg_duration,
        COUNT(CASE WHEN actual_end > scheduled_end THEN 1 END) AS late_returns
    FROM 
        break_schedule
    WHERE 
        employee_id = ?
        AND break_start >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
");
$stats_stmt->bind_param("i", $employee_id);
$stats_stmt->execute();
$break_stats = $stats_stmt->get_result()->fetch_assoc();

// Helper function to get status badge
function getStatusBadge($status, $class) {
    return '<span class="badge bg-' . $class . '">' . $status . '</span>';
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    
    <!-- Prevent form resubmission when refreshing the page -->
    <script>
        if (window.history.replaceState) {
            window.history.replaceState(null, null, window.location.href);
        }
    </script>
    
    <title>Break Management - <?= htmlspecialchars($employee['name']) ?></title>
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
        }
        
        .header {
            background: var(--primary-gradient);
            color: white;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 6px 15px rgba(0, 0, 0, 0.08);
        }
        
        .card {
            border: none;
            border-radius: 12px;
            box-shadow: 0 6px 15px rgba(0, 0, 0, 0.08);
            margin-bottom: 20px;
            overflow: hidden;
        }
        
        .card-header {
            background: var(--primary-gradient);
            color: white;
            border-bottom: none;
            padding: 15px 20px;
            font-weight: 600;
        }
        
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
            color: #333;
        }
        
        .stat-card .title {
            color: #6c757d;
            font-size: 1rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 500;
        }
        
        .break-timer {
            font-family: monospace;
            font-size: 2rem;
            padding: 15px;
            border-radius: 8px;
            background-color: #f8d7da;
            color: #721c24;
            text-align: center;
            margin: 15px 0;
        }
    </style>
</head>
<body>
    <div class="container py-4">
        <div class="header d-flex justify-content-between align-items-center">
            <h2><i class="bi bi-cup-hot me-2"></i>Break Management</h2>
            <div>
                <a href="admin.php" class="btn btn-light">
                    <i class="bi bi-arrow-left me-1"></i> Back to Admin
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
            <!-- Employee Info -->
            <div class="col-md-4 mb-4">
                <div class="card">
                    <div class="card-header">
                        <i class="bi bi-person-badge me-2"></i>Employee Information
                    </div>
                    <div class="card-body">
                        <div class="text-center mb-4">
                            <img src="https://via.placeholder.com/100" class="rounded-circle mb-3" alt="<?= htmlspecialchars($employee['name']) ?>">
                            <h4><?= htmlspecialchars($employee['name']) ?></h4>
                            <div class="badge bg-primary mb-2">Employee ID: <?= $employee['id'] ?></div>
                        </div>
                        
                        <div class="list-group">
                            <div class="list-group-item d-flex justify-content-between align-items-center">
                                <span><i class="bi bi-envelope me-2"></i>Email</span>
                                <span class="fw-bold"><?= htmlspecialchars($employee['email']) ?></span>
                            </div>
                            <div class="list-group-item d-flex justify-content-between align-items-center">
                                <span><i class="bi bi-calendar me-2"></i>Date</span>
                                <span class="fw-bold"><?= date('l, F j, Y') ?></span>
                            </div>
                            <div class="list-group-item d-flex justify-content-between align-items-center">
                                <span><i class="bi bi-clock me-2"></i>Status</span>
                                <span class="fw-bold">
                                    <?php
                                    if (!$attendance) {
                                        echo getStatusBadge('Not Started', 'secondary');
                                    } elseif ($attendance['check_out']) {
                                        echo getStatusBadge('Completed', 'success');
                                    } elseif ($attendance['break_end']) {
                                        echo getStatusBadge('After Break', 'info');
                                    } elseif ($attendance['break_start']) {
                                        echo getStatusBadge('On Break', 'warning');
                                    } elseif ($attendance['check_in']) {
                                        echo getStatusBadge('Working', 'primary');
                                    }
                                    ?>
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Break Actions Card -->
                <div class="card">
                    <div class="card-header bg-warning text-white">
                        <i class="bi bi-cup-hot me-2"></i>Break Actions
                    </div>
                    <div class="card-body">
                        <?php if (!$attendance || !$attendance['check_in'] || $attendance['check_out']): ?>
                            <div class="alert alert-info">
                                <i class="bi bi-info-circle-fill me-2"></i>
                                Employee must be checked in to manage breaks.
                            </div>
                        <?php elseif ($attendance['break_start'] && !$attendance['break_end']): ?>
                            <div class="alert alert-warning">
                                <i class="bi bi-exclamation-triangle-fill me-2"></i>
                                This employee is currently on a break
                            </div>
                            
                            <?php
                            // Display timer
                            // Get server time for accurate calculations
                            $server_time_query = $conn->query("SELECT NOW() as server_time");
                            $server_time_row = $server_time_query->fetch_assoc();
                            $server_now = new DateTime($server_time_row['server_time']);
                            
                            $break_start = new DateTime($attendance['break_start']);
                            $elapsed = $break_start->diff($server_now);
                            $elapsed_hours = $elapsed->h + ($elapsed->days * 24); // Include days in hours calculation
                            $elapsed_minutes = intval($elapsed->i);
                            $elapsed_seconds = intval($elapsed->s);
                            
                            // Ensure we always have numeric values
                            if (!is_numeric($elapsed_hours)) $elapsed_hours = 0;
                            if (!is_numeric($elapsed_minutes)) $elapsed_minutes = 0;
                            if (!is_numeric($elapsed_seconds)) $elapsed_seconds = 0;
                            
                            // Calculate total seconds elapsed for JavaScript
                            $total_seconds_elapsed = ($elapsed_hours * 3600) + ($elapsed_minutes * 60) + $elapsed_seconds;
                            ?>
                            
                            <div class="break-timer" 
                                data-start-time="<?= $attendance['break_start'] ?>" 
                                data-server-time="<?= $server_time_row['server_time'] ?>"
                                data-elapsed-seconds="<?= $total_seconds_elapsed ?>">
                                <?= sprintf('%02d:%02d:%02d', $elapsed_hours, $elapsed_minutes, $elapsed_seconds) ?>
                            </div>
                            
                            <form method="POST" action="">
                                <input type="hidden" name="id" value="<?= $employee_id ?>">
                                <div class="d-grid">
                                    <button type="submit" name="end_break" class="btn btn-danger btn-lg">
                                        <i class="bi bi-cup me-2"></i>End Break Now
                                    </button>
                                </div>
                            </form>
                        <?php else: ?>
                            <form method="POST" action="">
                                <input type="hidden" name="id" value="<?= $employee_id ?>">
                                
                                <div class="mb-3">
                                    <label for="break_minutes" class="form-label">Break Duration (minutes)</label>
                                    <div class="input-group">
                                        <input type="number" class="form-control" id="break_minutes" name="break_minutes" min="5" max="60" value="15" required>
                                        <span class="input-group-text">minutes</span>
                                    </div>
                                    <small class="text-muted">Set how long the break should last (5-60 minutes)</small>
                                </div>
                                
                                <div class="mb-3">
                                    <label class="form-label">Break Type</label>
                                    <div class="form-check">
                                        <input class="form-check-input" type="radio" name="break_type" id="lunchBreak" value="lunch" checked>
                                        <label class="form-check-label" for="lunchBreak">
                                            <i class="bi bi-cup-hot me-1"></i> Lunch Break
                                        </label>
                                    </div>
                                    <div class="form-check">
                                        <input class="form-check-input" type="radio" name="break_type" id="restBreak" value="rest">
                                        <label class="form-check-label" for="restBreak">
                                            <i class="bi bi-clock-history me-1"></i> Rest Break
                                        </label>
                                    </div>
                                </div>
                                
                                <div class="d-grid gap-2">
                                    <button type="submit" name="add_break" class="btn btn-warning btn-lg">
                                        <i class="bi bi-cup-hot me-2"></i> Start Break Now
                                    </button>
                                </div>
                            </form>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
            
            <!-- Break Statistics and History -->
            <div class="col-md-8">
                <!-- Break Statistics -->
                <?php if ($break_stats && $break_stats['total_breaks'] > 0): ?>
                <div class="card mb-4">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <div><i class="bi bi-bar-chart-fill me-2"></i>Break Statistics (Last 30 Days)</div>
                        <form method="post" action="export_stats.php">
                            <input type="hidden" name="employee_id" value="<?= $employee_id ?>">
                            <button type="submit" class="btn btn-sm btn-primary">
                                <i class="bi bi-file-excel me-1"></i> Export Stats
                            </button>
                        </form>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-4 mb-3">
                                <div class="stat-card bg-white">
                                    <div class="icon">
                                        <i class="bi bi-calendar-check"></i>
                                    </div>
                                    <p class="number"><?= $break_stats['total_breaks'] ?></p>
                                    <p class="title">Total Breaks</p>
                                </div>
                            </div>
                            <div class="col-md-4 mb-3">
                                <div class="stat-card bg-white">
                                    <div class="icon">
                                        <i class="bi bi-clock-history"></i>
                                    </div>
                                    <p class="number"><?= ceil($break_stats['total_minutes']) ?></p>
                                    <p class="title">Total Minutes</p>
                                </div>
                            </div>
                            <div class="col-md-4 mb-3">
                                <div class="stat-card bg-white">
                                    <div class="icon">
                                        <i class="bi bi-stopwatch"></i>
                                    </div>
                                    <p class="number"><?= round($break_stats['avg_duration']) ?></p>
                                    <p class="title">Avg. Minutes</p>
                                </div>
                            </div>
                        </div>
                        <div class="row mt-2">
                            <div class="col-md-4 mb-3">
                                <div class="stat-card bg-white">
                                    <div class="icon">
                                        <i class="bi bi-cup-hot"></i>
                                    </div>
                                    <p class="number"><?= $break_stats['lunch_breaks'] ?></p>
                                    <p class="title">Lunch Breaks</p>
                                </div>
                            </div>
                            <div class="col-md-4 mb-3">
                                <div class="stat-card bg-white">
                                    <div class="icon">
                                        <i class="bi bi-cup"></i>
                                    </div>
                                    <p class="number"><?= $break_stats['rest_breaks'] ?></p>
                                    <p class="title">Rest Breaks</p>
                                </div>
                            </div>
                            <div class="col-md-4 mb-3">
                                <div class="stat-card bg-white">
                                    <div class="icon">
                                        <i class="bi bi-exclamation-triangle"></i>
                                    </div>
                                    <p class="number"><?= $break_stats['late_returns'] ?></p>
                                    <p class="title">Late Returns</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
                
                <!-- Break History -->
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <div><i class="bi bi-list-ul me-2"></i>Break History</div>
                        <form method="post" action="export_breaks.php">
                            <input type="hidden" name="employee_id" value="<?= $employee_id ?>">
                            <button type="submit" class="btn btn-sm btn-success">
                                <i class="bi bi-file-excel me-1"></i> Export to Excel
                            </button>
                        </form>
                    </div>
                    <div class="card-body">
                        <?php if ($break_history && $break_history->num_rows > 0): ?>
                            <div class="table-responsive">
                                <table class="table table-striped table-bordered table-hover">
                                    <thead>
                                        <tr>
                                            <th>Date</th>
                                            <th>Type</th>
                                            <th>Start Time</th>
                                            <th>End Time</th>
                                            <th>Duration</th>
                                            <th>Status</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php while ($break = $break_history->fetch_assoc()): 
                                            $start_time = new DateTime($break['break_start']);
                                            $status = "Completed";
                                            $status_class = "success";
                                            
                                            if ($break['actual_end'] === NULL) {
                                                $end_time = "In Progress";
                                                $status = "Active";
                                                $status_class = "warning";
                                            } else {
                                                $end_time = new DateTime($break['actual_end']);
                                                $end_time = $end_time->format('h:i:s A');
                                            }
                                            
                                            // Calculate if break ended early or late
                                            if ($break['actual_end'] !== NULL) {
                                                $actual_end = new DateTime($break['actual_end']);
                                                $scheduled_end = new DateTime($break['scheduled_end']);
                                                
                                                $diff = $actual_end->getTimestamp() - $scheduled_end->getTimestamp();
                                                if ($diff > 60) {
                                                    $status = "Ended Late";
                                                    $status_class = "danger";
                                                } elseif ($diff < -60) {
                                                    $status = "Ended Early";
                                                    $status_class = "info";
                                                }
                                            }
                                        ?>
                                            <tr>
                                                <td><?= $start_time->format('Y-m-d') ?></td>
                                                <td>
                                                    <?php if ($break['break_type'] == 'lunch'): ?>
                                                        <span class="badge bg-primary">
                                                            <i class="bi bi-cup-hot me-1"></i>Lunch
                                                        </span>
                                                    <?php else: ?>
                                                        <span class="badge bg-info">
                                                            <i class="bi bi-clock-history me-1"></i>Rest
                                                        </span>
                                                    <?php endif; ?>
                                                </td>
                                                <td><?= $start_time->format('h:i:s A') ?></td>
                                                <td><?= $end_time ?></td>
                                                <td><?= $break['duration_minutes'] ?> min</td>
                                                <td>
                                                    <span class="badge bg-<?= $status_class ?>">
                                                        <?= $status ?>
                                                    </span>
                                                </td>
                                            </tr>
                                        <?php endwhile; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php else: ?>
                            <div class="alert alert-info">
                                <i class="bi bi-info-circle-fill me-2"></i>
                                No break history found for this employee.
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Auto-update break timer
        document.addEventListener('DOMContentLoaded', function() {
            const breakTimer = document.querySelector('.break-timer');
            
            if (breakTimer) {
                try {
                    // Get elapsed seconds directly from data attribute (more reliable)
                    let totalSeconds = parseInt(breakTimer.getAttribute('data-elapsed-seconds')) || 0;
                    
                    // If we don't have valid elapsed seconds, calculate from times
                    if (isNaN(totalSeconds) || totalSeconds <= 0) {
                        // Get the initial start time and server time from data attributes
                        const startTimeStr = breakTimer.getAttribute('data-start-time');
                        const serverTimeStr = breakTimer.getAttribute('data-server-time');
                        
                        if (!startTimeStr || !serverTimeStr) {
                            console.error("Missing time data attributes");
                            breakTimer.textContent = '00:00:00';
                            return;
                        }
                        
                        const startTime = new Date(startTimeStr);
                        const serverTime = new Date(serverTimeStr);
                        const clientTime = new Date();
                        
                        // Make sure we have valid dates
                        if (isNaN(startTime.getTime()) || isNaN(serverTime.getTime())) {
                            console.error("Invalid date values", { startTime, serverTime });
                            breakTimer.textContent = '00:00:00';
                            return;
                        }
                        
                        // Calculate server-client time offset to maintain accuracy
                        const timeOffset = serverTime.getTime() - clientTime.getTime();
                        
                        // Calculate initial seconds from server time
                        const initialServerDiff = Math.floor((serverTime.getTime() - startTime.getTime()) / 1000);
                        if (initialServerDiff > 0) {
                            totalSeconds = initialServerDiff;
                        }
                    }
                    
                    console.log("Initial seconds:", totalSeconds);
                    
                    // Update the display initially
                    updateTimerDisplay(totalSeconds);
                    
                    // Update the timer every second
                    const interval = setInterval(function() {
                        try {
                            // Increment total seconds
                            totalSeconds++;
                            
                            // Update the display
                            updateTimerDisplay(totalSeconds);
                        } catch (error) {
                            console.error("Error updating break timer:", error);
                            breakTimer.textContent = '00:00:00'; // Fallback display
                        }
                    }, 1000);
                    
                    // Helper function to update the display
                    function updateTimerDisplay(totalSeconds) {
                        if (isNaN(totalSeconds) || totalSeconds < 0) {
                            totalSeconds = 0;
                        }
                        
                        // Convert to hours, minutes, seconds
                        const hours = Math.floor(totalSeconds / 3600);
                        const minutes = Math.floor((totalSeconds % 3600) / 60);
                        const seconds = totalSeconds % 60;
                        
                        // Format with leading zeros
                        const formattedHours = String(hours).padStart(2, '0');
                        const formattedMinutes = String(minutes).padStart(2, '0');
                        const formattedSeconds = String(seconds).padStart(2, '0');
                        
                        // Update the display
                        breakTimer.textContent = `${formattedHours}:${formattedMinutes}:${formattedSeconds}`;
                    }
                } catch (error) {
                    console.error("Error initializing break timer:", error);
                    breakTimer.textContent = '00:00:00'; // Fallback display
                }
            }
        });
    </script>
</body>
</html> 