<?php
session_start();
require 'db.php';
require 'theme_helper.php'; // Include theme helper

// Get theme color from cookie or database
$theme_color = getThemeColor($conn);

// Verify user session
if (!isset($_SESSION['employee_id']) || !isset($_SESSION['session_id'])) {
    header("Location: login.php");
    exit;
}

// Set security headers
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:;");

$employee_id = $_SESSION['employee_id'];
$message = '';
$error_message = '';

// Handle task update
if (isset($_POST['update_task'])) {
    $task_id = intval($_POST['task_id']);
    $status = $_POST['status'];
    $notes = trim($_POST['notes']);
    
    // Verify this task belongs to the logged-in employee
    $check_task = $conn->prepare("SELECT id FROM employee_tasks WHERE id = ? AND employee_id = ?");
    $check_task->bind_param("ii", $task_id, $employee_id);
    $check_task->execute();
    $task_result = $check_task->get_result();
    
    if ($task_result->num_rows > 0) {
        $completed_at = ($status === 'completed') ? "completed_at = NOW()" : "completed_at = NULL";
        
        $sql = "UPDATE employee_tasks SET status = ?, notes = ?, $completed_at WHERE id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ssi", $status, $notes, $task_id);
        
        if ($stmt->execute()) {
            $message = "Task updated successfully";
            
            // Add record to admin_alerts
            $employee_query = $conn->prepare("SELECT name FROM employees WHERE id = ?");
            $employee_query->bind_param("i", $employee_id);
            $employee_query->execute();
            $employee_result = $employee_query->get_result();
            $employee_name = "Employee";
            if ($employee_row = $employee_result->fetch_assoc()) {
                $employee_name = $employee_row['name'];
            }
            
            $task_query = $conn->prepare("SELECT task_description FROM employee_tasks WHERE id = ?");
            $task_query->bind_param("i", $task_id);
            $task_query->execute();
            $task_result = $task_query->get_result();
            $task_desc = "task";
            if ($task_row = $task_result->fetch_assoc()) {
                $task_desc = $task_row['task_description'];
            }
            
            $alert_message = $employee_name . " updated task status to " . $status . ": " . $task_desc;
            $alert_stmt = $conn->prepare("INSERT INTO admin_alerts (employee_id, message, device_info, is_read) VALUES (?, ?, 'Employee update', 0)");
            $alert_stmt->bind_param("is", $employee_id, $alert_message);
            $alert_stmt->execute();
        } else {
            $error_message = "Error updating task: " . $stmt->error;
        }
    } else {
        $error_message = "You don't have permission to update this task";
    }
}

// Get employee info
$emp_query = $conn->prepare("SELECT name FROM employees WHERE id = ?");
$emp_query->bind_param("i", $employee_id);
$emp_query->execute();
$emp_result = $emp_query->get_result();
$employee_name = "Employee";
if ($emp_row = $emp_result->fetch_assoc()) {
    $employee_name = $emp_row['name'];
}

// Get tasks for this employee
$tasks_query = $conn->prepare("
    SELECT 
        et.*,
        e.name AS admin_name
    FROM 
        employee_tasks et
    LEFT JOIN 
        employees e ON et.created_by = e.id
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
$stats_result = $stats_query->get_result();
$task_stats = $stats_result->fetch_assoc();
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
    
    <title>My Tasks</title>
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
        
        .header h2 {
            margin: 0;
            font-weight: 600;
        }
        
        .task-card {
            border-radius: 10px;
            border: none;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            margin-bottom: 20px;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            border-top: 3px solid var(--primary-color);
        }
        
        .task-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 15px rgba(0, 0, 0, 0.1);
        }
        
        .priority-high {
            border-left: 5px solid #dc3545;
        }
        
        .priority-medium {
            border-left: 5px solid #ffc107;
        }
        
        .priority-low {
            border-left: 5px solid #0dcaf0;
        }
        
        .status-badge {
            font-size: 0.8rem;
            padding: 0.35em 0.65em;
        }
        
        .task-date {
            font-size: 0.8rem;
            color: #6c757d;
        }
        
        .stats-card {
            border-radius: 10px;
            text-align: center;
            border: none;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            transition: all 0.3s ease;
            border-top: 3px solid var(--primary-color);
        }
        
        .stats-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 15px rgba(0, 0, 0, 0.1);
        }
        
        .stats-card .number {
            font-size: 2rem;
            font-weight: bold;
            color: var(--primary-color);
        }
        
        .stats-card .title {
            font-size: 0.9rem;
            color: #6c757d;
            margin-top: 5px;
        }
        
        .completed-task {
            background-color: rgba(240, 255, 240, 0.5);
        }
        
        .completed-task .task-description {
            text-decoration: line-through;
            color: #6c757d;
        }
        
        .due-date-alert {
            color: #dc3545;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 5px;
            font-size: 0.9rem;
        }
        
        .btn-action {
            padding: 0.25rem 0.5rem;
            font-size: 0.8rem;
        }
        
        @media (max-width: 768px) {
            .header {
                padding: 15px;
                margin-bottom: 15px;
            }
            
            .header h2 {
                font-size: 1.5rem;
            }
            
            .stats-row .col-6 {
                margin-bottom: 15px;
            }
            
            .stats-card .number {
                font-size: 1.5rem;
            }
        }
    </style>
</head>
<body>
    <div class="container py-4">
        <div class="header d-flex justify-content-between align-items-center">
            <div>
                <h2><i class="bi bi-list-check me-2"></i>My Tasks</h2>
                <p class="mb-0">Welcome, <?= htmlspecialchars($employee_name) ?></p>
            </div>
            <div>
                <a href="attendance.php" class="btn btn-light">
                    <i class="bi bi-arrow-left me-1"></i> Back to Dashboard
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

        <!-- Stats Row -->
        <div class="row stats-row mb-4">
            <div class="col-6 col-md-3">
                <div class="stats-card bg-white p-3">
                    <div class="number text-primary"><?= $task_stats['total'] ?? 0 ?></div>
                    <div class="title">Total Tasks</div>
                </div>
            </div>
            <div class="col-6 col-md-3">
                <div class="stats-card bg-white p-3">
                    <div class="number text-warning"><?= $task_stats['pending'] ?? 0 ?></div>
                    <div class="title">Pending</div>
                </div>
            </div>
            <div class="col-6 col-md-3">
                <div class="stats-card bg-white p-3">
                    <div class="number text-success"><?= $task_stats['completed'] ?? 0 ?></div>
                    <div class="title">Completed</div>
                </div>
            </div>
            <div class="col-6 col-md-3">
                <div class="stats-card bg-white p-3">
                    <div class="number text-danger"><?= $task_stats['overdue'] ?? 0 ?></div>
                    <div class="title">Overdue</div>
                </div>
            </div>
        </div>

        <!-- Tasks Section -->
        <h4 class="mb-3">Your Assigned Tasks</h4>
        
        <div class="row">
            <?php if ($tasks_result->num_rows > 0): ?>
                <?php while ($task = $tasks_result->fetch_assoc()): ?>
                    <div class="col-md-6 mb-4">
                        <div class="card task-card priority-<?= $task['priority'] ?> <?= $task['status'] === 'completed' ? 'completed-task' : '' ?>">
                            <div class="card-body">
                                <div class="d-flex justify-content-between align-items-start mb-2">
                                    <h5 class="card-title task-description"><?= htmlspecialchars($task['task_description']) ?></h5>
                                    <div>
                                        <?php 
                                        switch($task['status']) {
                                            case 'pending':
                                                echo '<span class="badge bg-warning status-badge">Pending</span>';
                                                break;
                                            case 'completed':
                                                echo '<span class="badge bg-success status-badge">Completed</span>';
                                                break;
                                            case 'in_progress':
                                                echo '<span class="badge bg-info status-badge">In Progress</span>';
                                                break;
                                        }
                                        ?>
                                        <span class="badge bg-<?= 
                                            $task['priority'] === 'high' ? 'danger' : 
                                            ($task['priority'] === 'medium' ? 'warning' : 'info') 
                                        ?> status-badge">
                                            <?= ucfirst($task['priority']) ?> Priority
                                        </span>
                                    </div>
                                </div>
                                
                                <?php if ($task['due_date']): ?>
                                    <p class="mb-2">
                                        <?php 
                                        $due_date = new DateTime($task['due_date']);
                                        $today = new DateTime();
                                        $is_overdue = $due_date < $today && $task['status'] !== 'completed';
                                        ?>
                                        
                                        <?php if ($is_overdue): ?>
                                            <span class="due-date-alert">
                                                <i class="bi bi-exclamation-triangle-fill"></i> 
                                                Overdue: Due <?= $due_date->format('M j, Y') ?>
                                            </span>
                                        <?php else: ?>
                                            <strong>Due Date:</strong> <?= $due_date->format('M j, Y') ?>
                                        <?php endif; ?>
                                    </p>
                                <?php endif; ?>
                                
                                <?php if ($task['notes']): ?>
                                    <p class="card-text mb-2">
                                        <strong>Notes:</strong> <?= htmlspecialchars($task['notes']) ?>
                                    </p>
                                <?php endif; ?>
                                
                                <div class="d-flex justify-content-between align-items-center mt-3">
                                    <div class="task-date">
                                        <small>
                                            Assigned: <?= date('M j, Y', strtotime($task['created_at'])) ?>
                                            <?php if ($task['completed_at']): ?>
                                                | Completed: <?= date('M j, Y', strtotime($task['completed_at'])) ?>
                                            <?php endif; ?>
                                        </small>
                                    </div>
                                    
                                    <button type="button" class="btn btn-sm btn-primary" data-bs-toggle="modal" data-bs-target="#updateTaskModal<?= $task['id'] ?>">
                                        <?= $task['status'] === 'completed' ? '<i class="bi bi-eye"></i> View' : '<i class="bi bi-pencil-square"></i> Update' ?>
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Update Task Modal -->
                    <div class="modal fade" id="updateTaskModal<?= $task['id'] ?>" tabindex="-1" aria-labelledby="updateTaskModalLabel<?= $task['id'] ?>" aria-hidden="true">
                        <div class="modal-dialog">
                            <div class="modal-content">
                                <div class="modal-header">
                                    <h5 class="modal-title" id="updateTaskModalLabel<?= $task['id'] ?>">
                                        <i class="bi bi-list-check me-1"></i> Update Task Status
                                    </h5>
                                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                </div>
                                <div class="modal-body">
                                    <form method="POST" action="">
                                        <input type="hidden" name="task_id" value="<?= $task['id'] ?>">
                                        
                                        <div class="mb-3">
                                            <label class="form-label">Task Description:</label>
                                            <p class="form-control-static"><?= htmlspecialchars($task['task_description']) ?></p>
                                        </div>
                                        
                                        <div class="mb-3">
                                            <label class="form-label">Priority:</label>
                                            <p class="form-control-static">
                                                <span class="badge bg-<?= 
                                                    $task['priority'] === 'high' ? 'danger' : 
                                                    ($task['priority'] === 'medium' ? 'warning' : 'info') 
                                                ?>">
                                                    <?= ucfirst($task['priority']) ?>
                                                </span>
                                            </p>
                                        </div>
                                        
                                        <?php if ($task['due_date']): ?>
                                            <div class="mb-3">
                                                <label class="form-label">Due Date:</label>
                                                <p class="form-control-static"><?= date('M j, Y', strtotime($task['due_date'])) ?></p>
                                            </div>
                                        <?php endif; ?>
                                        
                                        <div class="mb-3">
                                            <label for="status<?= $task['id'] ?>" class="form-label">Status</label>
                                            <select class="form-select" id="status<?= $task['id'] ?>" name="status" required>
                                                <option value="pending" <?= $task['status'] === 'pending' ? 'selected' : '' ?>>Pending</option>
                                                <option value="in_progress" <?= $task['status'] === 'in_progress' ? 'selected' : '' ?>>In Progress</option>
                                                <option value="completed" <?= $task['status'] === 'completed' ? 'selected' : '' ?>>Completed</option>
                                            </select>
                                        </div>
                                        
                                        <div class="mb-3">
                                            <label for="notes<?= $task['id'] ?>" class="form-label">Add Notes (Optional)</label>
                                            <textarea class="form-control" id="notes<?= $task['id'] ?>" name="notes" rows="3"><?= htmlspecialchars($task['notes']) ?></textarea>
                                        </div>
                                        
                                        <div class="modal-footer p-0 pt-3 border-0">
                                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                            <button type="submit" name="update_task" class="btn btn-primary">Update Status</button>
                                        </div>
                                    </form>
                                </div>
                            </div>
                        </div>
                    </div>
                <?php endwhile; ?>
            <?php else: ?>
                <div class="col-12">
                    <div class="alert alert-info">
                        <i class="bi bi-info-circle-fill me-2"></i>
                        You don't have any assigned tasks at the moment.
                    </div>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html> 