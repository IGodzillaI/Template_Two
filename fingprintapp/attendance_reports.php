<?php
session_name('admin_session');
session_start();
require 'db.php';
require 'theme_helper.php'; // Include theme helper

// Get admin theme color
$theme_color = getAdminThemeColor($conn);

// Verify admin session
if (!isset($_SESSION['is_admin']) || !isset($_SESSION['admin_cookie']) || !isset($_SESSION['admin_id'])) {
    session_unset();
    session_destroy();
    header("Location: admin_login.php");
    exit;
}

// Set security headers
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:;");

// Initialize message variables
$message = '';
$error_message = '';

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Add new task
    if (isset($_POST['add_task'])) {
        $employee_id = intval($_POST['employee_id']);
        $task_description = trim($_POST['task_description']);
        $due_date = !empty($_POST['due_date']) ? $_POST['due_date'] : NULL;
        $priority = $_POST['priority'];
        $notes = trim($_POST['notes']);
        
        if (empty($task_description)) {
            $error_message = "Task description cannot be empty";
        } else {
            $stmt = $conn->prepare("INSERT INTO employee_tasks (employee_id, task_description, due_date, priority, created_by, notes) VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->bind_param("isssis", $employee_id, $task_description, $due_date, $priority, $_SESSION['admin_id'], $notes);
            
            if ($stmt->execute()) {
                $message = "Task added successfully";
                
                // Add record to admin_alerts
                $employee_query = $conn->prepare("SELECT name FROM employees WHERE id = ?");
                $employee_query->bind_param("i", $employee_id);
                $employee_query->execute();
                $employee_result = $employee_query->get_result();
                $employee_name = "Employee";
                if ($employee_row = $employee_result->fetch_assoc()) {
                    $employee_name = $employee_row['name'];
                }
                
                $alert_message = "New task assigned to " . $employee_name . ": " . $task_description;
                $alert_stmt = $conn->prepare("INSERT INTO admin_alerts (employee_id, message, device_info, is_read) VALUES (?, ?, 'Admin action from dashboard', 0)");
                $alert_stmt->bind_param("is", $employee_id, $alert_message);
                $alert_stmt->execute();
            } else {
                $error_message = "Error adding task: " . $stmt->error;
            }
        }
    }
    
    // Update task status
    if (isset($_POST['update_task'])) {
        $task_id = intval($_POST['task_id']);
        $status = $_POST['status'];
        $notes = trim($_POST['notes']);
        
        $completed_at = ($status === 'completed') ? "completed_at = NOW()" : "completed_at = NULL";
        
        $sql = "UPDATE employee_tasks SET status = ?, notes = ?, $completed_at WHERE id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ssi", $status, $notes, $task_id);
        
        if ($stmt->execute()) {
            $message = "Task updated successfully";
        } else {
            $error_message = "Error updating task: " . $stmt->error;
        }
    }
    
    // Delete task
    if (isset($_POST['delete_task'])) {
        $task_id = intval($_POST['task_id']);
        
        $stmt = $conn->prepare("DELETE FROM employee_tasks WHERE id = ?");
        $stmt->bind_param("i", $task_id);
        
        if ($stmt->execute()) {
            $message = "Task deleted successfully";
        } else {
            $error_message = "Error deleting task: " . $stmt->error;
        }
    }
}

// Get selected employee ID from URL parameter
$selected_employee_id = isset($_GET['employee_id']) ? intval($_GET['employee_id']) : 0;

// Fetch employees
$employees = $conn->query("SELECT id, name FROM employees ORDER BY name ASC");

// Default to showing all tasks if no employee is selected
$where_clause = $selected_employee_id > 0 ? "WHERE et.employee_id = $selected_employee_id" : "";

// Fetch tasks with employee names
$tasks_query = $conn->query("
    SELECT 
        et.*,
        e.name AS employee_name,
        a.name AS admin_name
    FROM 
        employee_tasks et
    JOIN 
        employees e ON et.employee_id = e.id
    LEFT JOIN 
        employees a ON et.created_by = a.id
    $where_clause
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

// Get task statistics
$task_stats = [
    'total' => 0,
    'pending' => 0,
    'completed' => 0,
    'in_progress' => 0,
    'overdue' => 0
];

$stats_query = $conn->query("
    SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
        SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
        SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END) as in_progress,
        SUM(CASE WHEN status = 'pending' AND due_date < CURDATE() THEN 1 ELSE 0 END) as overdue
    FROM employee_tasks
    " . ($selected_employee_id > 0 ? "WHERE employee_id = $selected_employee_id" : "")
);

if ($stats_row = $stats_query->fetch_assoc()) {
    $task_stats = $stats_row;
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
    
    <title>Attendance Reports & Task Management</title>
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
        
        .task-card {
            border-radius: 10px;
            border: none;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            margin-bottom: 20px;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
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
        
        /* Theme-specific buttons */
        .btn-primary {
            background: var(--primary-gradient);
            border: none;
        }
        
        .btn-primary:hover {
            background: linear-gradient(135deg, var(--primary-dark) 0%, var(--secondary-color) 100%);
        }
        
        .status-badge {
            font-size: 0.8rem;
            padding: 0.35em 0.65em;
        }
        
        .task-actions {
            display: flex;
            gap: 5px;
        }
        
        .task-date {
            font-size: 0.8rem;
            color: #6c757d;
        }
        
        .stats-card {
            border-radius: 10px;
            border: none;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            transition: all 0.3s ease;
            min-height: 100%;
            position: relative;
            overflow: hidden;
        }
        
        .stats-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 15px rgba(0, 0, 0, 0.1);
        }
        
        .stats-card .icon {
            position: absolute;
            bottom: -15px;
            right: -15px;
            font-size: 5rem;
            opacity: 0.1;
            transform: rotate(-15deg);
        }
        
        .stats-card .card-body {
            position: relative;
            z-index: 1;
        }
        
        .stats-card .number {
            font-size: 2rem;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .stats-card .title {
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 500;
            font-size: 0.8rem;
            margin-bottom: 0;
        }
        
        .btn-action {
            padding: 0.25rem 0.5rem;
            font-size: 0.8rem;
        }
        
        .due-date-alert {
            color: #dc3545;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 5px;
            font-size: 0.9rem;
        }
        
        .filter-form .btn, .filter-form .form-select {
            padding: 0.5rem 1rem;
            font-size: 0.875rem;
        }
        
        .completed-task {
            background-color: rgba(240, 255, 240, 0.5);
        }
        
        .completed-task .task-description {
            text-decoration: line-through;
            color: #6c757d;
        }
        
        @media (max-width: 768px) {
            .dashboard-header {
                padding: 15px;
                margin-bottom: 15px;
            }
            
            .dashboard-header h2 {
                font-size: 1.5rem;
            }
            
            .stat-cards .col-md-3 {
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
        <div class="dashboard-header d-flex justify-content-between align-items-center mb-4">
            <div>
                <h2><i class="bi bi-clipboard-data me-2"></i>Attendance Reports & Tasks</h2>
                <p class="mb-0">Manage employee tasks and view attendance reports</p>
            </div>
            <div class="header-actions">
                <a href="admin.php?view=dashboard" class="btn btn-light">
                    <i class="bi bi-arrow-left me-1"></i> Back to Dashboard
                </a>
                <button type="button" class="btn btn-success ms-2" data-bs-toggle="modal" data-bs-target="#addTaskModal">
                    <i class="bi bi-plus-circle me-1"></i> Add New Task
                </button>
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
        <div class="row mb-4">
            <div class="col-md-3 mb-3">
                <div class="stats-card text-white" style="background: var(--primary-gradient)">
                    <div class="card-body">
                        <p class="number"><?= $task_stats['total'] ?></p>
                        <p class="title">Total Tasks</p>
                        <div class="icon"><i class="bi bi-list-check"></i></div>
                    </div>
                </div>
            </div>
            <div class="col-md-3 mb-3">
                <div class="stats-card bg-warning text-dark">
                    <div class="card-body">
                        <p class="number"><?= $task_stats['pending'] ?></p>
                        <p class="title">Pending Tasks</p>
                        <div class="icon"><i class="bi bi-hourglass-split"></i></div>
                    </div>
                </div>
            </div>
            <div class="col-md-3 mb-3">
                <div class="stats-card bg-success text-white">
                    <div class="card-body">
                        <p class="number"><?= $task_stats['completed'] ?></p>
                        <p class="title">Completed Tasks</p>
                        <div class="icon"><i class="bi bi-check2-all"></i></div>
                    </div>
                </div>
            </div>
            <div class="col-md-3 mb-3">
                <div class="stats-card bg-danger text-white">
                    <div class="card-body">
                        <p class="number"><?= $task_stats['overdue'] ?></p>
                        <p class="title">Overdue Tasks</p>
                        <div class="icon"><i class="bi bi-exclamation-diamond"></i></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Filter Form -->
        <div class="card mb-4">
            <div class="card-body">
                <form action="" method="GET" class="row g-3 filter-form">
                    <div class="col-md-6">
                        <label for="employee_id" class="form-label">Filter by Employee</label>
                        <select class="form-select" id="employee_id" name="employee_id">
                            <option value="0">All Employees</option>
                            <?php if ($employees): while ($emp = $employees->fetch_assoc()): ?>
                                <option value="<?= $emp['id'] ?>" <?= $selected_employee_id == $emp['id'] ? 'selected' : '' ?>>
                                    <?= htmlspecialchars($emp['name']) ?>
                                </option>
                            <?php endwhile; endif; ?>
                        </select>
                    </div>
                    <div class="col-md-6 d-flex align-items-end">
                        <button type="submit" class="btn btn-primary">
                            <i class="bi bi-filter me-1"></i> Filter
                        </button>
                        <?php if ($selected_employee_id > 0): ?>
                            <a href="attendance_reports.php" class="btn btn-outline-secondary ms-2">
                                <i class="bi bi-x-circle me-1"></i> Clear Filter
                            </a>
                        <?php endif; ?>
                    </div>
                </form>
            </div>
        </div>

        <!-- Tasks Section -->
        <h4 class="mb-3">
            <?= $selected_employee_id > 0 ? 'Tasks for ' . htmlspecialchars($conn->query("SELECT name FROM employees WHERE id = $selected_employee_id")->fetch_assoc()['name']) : 'All Tasks' ?>
        </h4>
        
        <div class="row">
            <?php if ($tasks_query->num_rows > 0): ?>
                <?php while ($task = $tasks_query->fetch_assoc()): ?>
                    <div class="col-lg-6">
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
                                
                                <p class="card-text mb-2">
                                    <strong>Assigned to:</strong> <?= htmlspecialchars($task['employee_name']) ?>
                                </p>
                                
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
                                            Created: <?= date('M j, Y', strtotime($task['created_at'])) ?>
                                            <?php if ($task['completed_at']): ?>
                                                | Completed: <?= date('M j, Y', strtotime($task['completed_at'])) ?>
                                            <?php endif; ?>
                                        </small>
                                    </div>
                                    
                                    <div class="task-actions">
                                        <button type="button" class="btn btn-sm btn-primary btn-action" data-bs-toggle="modal" data-bs-target="#editTaskModal<?= $task['id'] ?>">
                                            <i class="bi bi-pencil-square"></i>
                                        </button>
                                        <form method="POST" action="" class="d-inline">
                                            <input type="hidden" name="task_id" value="<?= $task['id'] ?>">
                                            <button type="submit" name="delete_task" class="btn btn-sm btn-danger btn-action" onclick="return confirm('Are you sure you want to delete this task?')">
                                                <i class="bi bi-trash"></i>
                                            </button>
                                        </form>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Edit Task Modal -->
                    <div class="modal fade" id="editTaskModal<?= $task['id'] ?>" tabindex="-1" aria-labelledby="editTaskModalLabel<?= $task['id'] ?>" aria-hidden="true">
                        <div class="modal-dialog">
                            <div class="modal-content">
                                <div class="modal-header">
                                    <h5 class="modal-title" id="editTaskModalLabel<?= $task['id'] ?>">
                                        <i class="bi bi-pencil-square me-1"></i> Edit Task
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
                                            <label class="form-label">Assigned to:</label>
                                            <p class="form-control-static"><?= htmlspecialchars($task['employee_name']) ?></p>
                                        </div>
                                        
                                        <div class="mb-3">
                                            <label for="status<?= $task['id'] ?>" class="form-label">Status</label>
                                            <select class="form-select" id="status<?= $task['id'] ?>" name="status" required>
                                                <option value="pending" <?= $task['status'] === 'pending' ? 'selected' : '' ?>>Pending</option>
                                                <option value="in_progress" <?= $task['status'] === 'in_progress' ? 'selected' : '' ?>>In Progress</option>
                                                <option value="completed" <?= $task['status'] === 'completed' ? 'selected' : '' ?>>Completed</option>
                                            </select>
                                        </div>
                                        
                                        <div class="mb-3">
                                            <label for="notes<?= $task['id'] ?>" class="form-label">Notes</label>
                                            <textarea class="form-control" id="notes<?= $task['id'] ?>" name="notes" rows="3"><?= htmlspecialchars($task['notes']) ?></textarea>
                                        </div>
                                        
                                        <div class="modal-footer p-0 pt-3 border-0">
                                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                            <button type="submit" name="update_task" class="btn btn-primary">Update Task</button>
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
                        No tasks found. Click "Add New Task" to create tasks for employees.
                    </div>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <!-- Add Task Modal -->
    <div class="modal fade" id="addTaskModal" tabindex="-1" aria-labelledby="addTaskModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="addTaskModalLabel">
                        <i class="bi bi-plus-circle me-1"></i> Add New Task
                    </h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <form method="POST" action="">
                        <div class="mb-3">
                            <label for="employee_id_modal" class="form-label">Assign to Employee</label>
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
                        
                        <div class="mb-3">
                            <label for="task_description" class="form-label">Task Description</label>
                            <textarea class="form-control" id="task_description" name="task_description" rows="3" required></textarea>
                        </div>
                        
                        <div class="mb-3">
                            <label for="due_date" class="form-label">Due Date (Optional)</label>
                            <input type="date" class="form-control" id="due_date" name="due_date">
                        </div>
                        
                        <div class="mb-3">
                            <label for="priority" class="form-label">Priority</label>
                            <select class="form-select" id="priority" name="priority" required>
                                <option value="low">Low</option>
                                <option value="medium" selected>Medium</option>
                                <option value="high">High</option>
                            </select>
                        </div>
                        
                        <div class="mb-3">
                            <label for="notes" class="form-label">Notes (Optional)</label>
                            <textarea class="form-control" id="notes" name="notes" rows="2"></textarea>
                        </div>
                        
                        <div class="modal-footer p-0 pt-3 border-0">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                            <button type="submit" name="add_task" class="btn btn-success">Add Task</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html> 