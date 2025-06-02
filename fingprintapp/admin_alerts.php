<?php
session_name('admin_session');
session_start();
require 'db.php';
require 'theme_helper.php'; // Include theme helper

// Get the admin theme color
$theme_color = getAdminThemeColor($conn);

// Ensure database connection is active
$conn = ensureConnection($conn);
if (!$conn) {
    die("Database connection failed");
}

// Check if user is logged in as admin
if (!isset($_SESSION['is_admin']) || !isset($_SESSION['admin_id']) || !isset($_SESSION['admin_cookie'])) {
    header("Location: admin_login.php");
    exit;
}

// Verify admin session
$stmt = $conn->prepare("SELECT * FROM admin_sessions WHERE admin_id = ? AND session_id = ? AND last_activity > DATE_SUB(NOW(), INTERVAL 5 MINUTE)");
$stmt->bind_param("is", $_SESSION['admin_id'], $_SESSION['admin_cookie']);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    session_destroy();
    header("Location: admin_login.php");
    exit;
}

// Update last activity
$stmt = $conn->prepare("UPDATE admin_sessions SET last_activity = NOW() WHERE admin_id = ? AND session_id = ?");
$stmt->bind_param("is", $_SESSION['admin_id'], $_SESSION['admin_cookie']);
$stmt->execute();

// Get admin details
$stmt = $conn->prepare("SELECT * FROM admin WHERE id = ?");
$stmt->bind_param("i", $_SESSION['admin_id']);
$stmt->execute();
$admin = $stmt->get_result()->fetch_assoc();

if (!$admin) {
    session_destroy();
    header("Location: admin_login.php");
    exit;
}

// Mark all alerts as read if requested
if (isset($_POST['mark_all_read'])) {
    $conn->query("UPDATE admin_alerts SET is_read = 1");
    $_SESSION['success_message'] = "All alerts marked as read";
    header("Location: admin_alerts.php");
    exit;
}

// Clear all alerts if requested
if (isset($_POST['clear_all_alerts'])) {
    $conn->query("DELETE FROM admin_alerts");
    $_SESSION['success_message'] = "All alerts cleared successfully";
    header("Location: admin_alerts.php");
    exit;
}

// Mark alerts as read if requested
if (isset($_POST['mark_read']) && isset($_POST['alert_ids'])) {
    $alertIds = $_POST['alert_ids'];
    if (!empty($alertIds)) {
        $idList = implode(',', array_map('intval', $alertIds));
        $conn->query("UPDATE admin_alerts SET is_read = 1 WHERE id IN ($idList)");
        $_SESSION['success_message'] = "Alerts marked as read";
    }
}

// Delete alerts if requested
if (isset($_POST['delete_alerts']) && isset($_POST['alert_ids'])) {
    $alertIds = $_POST['alert_ids'];
    if (!empty($alertIds)) {
        $idList = implode(',', array_map('intval', $alertIds));
        $conn->query("DELETE FROM admin_alerts WHERE id IN ($idList)");
        $_SESSION['success_message'] = "Alerts deleted successfully";
    }
}

// Get all alerts
$filter = isset($_GET['filter']) ? $_GET['filter'] : 'all';
$whereClause = '';

if ($filter === 'unread') {
    $whereClause = 'WHERE is_read = 0';
} else if ($filter === 'today') {
    $whereClause = 'WHERE DATE(timestamp) = CURDATE()';
} else if ($filter === 'urgent') {
    $whereClause = 'WHERE message LIKE "%URGENT%"';
}

$query = "
    SELECT a.*, e.name as employee_name 
    FROM admin_alerts a 
    LEFT JOIN employees e ON a.employee_id = e.id 
    $whereClause
    ORDER BY a.timestamp DESC
";

$result = $conn->query($query);
$alerts = [];
if ($result) {
    while ($row = $result->fetch_assoc()) {
        $alerts[] = $row;
    }
}

// Count unread alerts
$unreadQuery = $conn->query("SELECT COUNT(*) as count FROM admin_alerts WHERE is_read = 0");
$unreadCount = $unreadQuery->fetch_assoc()['count'];

// Get message from session
$message = '';
if (isset($_SESSION['success_message'])) {
    $message = $_SESSION['success_message'];
    unset($_SESSION['success_message']);
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
    
    <title>Admin Alerts</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css">
    <style>
        :root {
            /* Theme color variables */
            <?= getThemeCSS($theme_color) ?>
        }
        
        body {
            background-color: #f8f9fa;
            padding-bottom: 40px;
        }
        
        .dashboard-header {
            background: var(--primary-gradient);
            color: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .alert-card {
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
            margin-bottom: 15px;
            border-left: 5px solid;
        }
        
        .alert-card.unread {
            border-left-color: #dc3545;
            background-color: #fff9f9;
        }
        
        .alert-card.read {
            border-left-color: #6c757d;
        }
        
        .alert-card.urgent {
            border-left-color: #dc3545;
            background-color: #ffecec;
        }
        
        .alert-header {
            display: flex;
            justify-content: space-between;
            border-bottom: 1px solid #f0f0f0;
            padding: 10px 15px;
        }
        
        .alert-body {
            padding: 15px;
        }
        
        .alert-footer {
            background-color: #f9f9f9;
            border-top: 1px solid #f0f0f0;
            padding: 10px 15px;
            border-bottom-left-radius: 10px;
            border-bottom-right-radius: 10px;
        }
        
        .badge-unread {
            background-color: #dc3545;
            color: white;
        }
        
        .filter-active {
            background-color: #4361ee !important;
            color: white !important;
        }
        
        /* Responsive styles for buttons */
        @media (max-width: 768px) {
            .btn-group {
                flex-wrap: wrap;
                margin-bottom: 10px;
            }
            
            .btn-group .btn {
                margin-bottom: 5px;
                flex: 1 0 auto;
            }
            
            .action-buttons-container {
                display: flex;
                flex-direction: column;
                gap: 5px;
            }
            
            .action-buttons-container button {
                margin-bottom: 5px;
                width: 100%;
                font-size: 0.85rem;
                padding: 6px 10px;
            }
        }
    </style>
</head>
<body>
    <div class="container py-4">
        <div class="dashboard-header d-flex justify-content-between align-items-center mb-4">
            <h2><i class="bi bi-bell-fill me-2"></i>Admin Alerts</h2>
            <div>
                <span class="badge rounded-pill bg-danger me-2">
                    <?= $unreadCount ?> Unread
                </span>
                <a href="admin.php?view=dashboard" class="btn btn-outline-light">
                    <i class="bi bi-speedometer me-1"></i>Back to Dashboard
                </a>
            </div>
        </div>
        
        <?php if (!empty($message)): ?>
        <div class="alert alert-success alert-dismissible fade show">
            <?= htmlspecialchars($message) ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
        <?php endif; ?>
        
        <div class="card mb-4">
            <div class="card-body">
                <form method="post">
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <div class="btn-group">
                            <a href="?filter=all" class="btn btn-outline-primary <?= $filter === 'all' ? 'filter-active' : '' ?>">
                                All Alerts
                            </a>
                            <a href="?filter=unread" class="btn btn-outline-primary <?= $filter === 'unread' ? 'filter-active' : '' ?>">
                                Unread
                            </a>
                            <a href="?filter=today" class="btn btn-outline-primary <?= $filter === 'today' ? 'filter-active' : '' ?>">
                                Today
                            </a>
                            <a href="?filter=urgent" class="btn btn-outline-primary <?= $filter === 'urgent' ? 'filter-active' : '' ?>">
                                Urgent
                            </a>
                        </div>
                        
                        <div class="action-buttons-container">
                            <button type="submit" name="mark_all_read" class="btn btn-outline-success" onclick="return confirm('Mark all alerts as read?')">
                                <i class="bi bi-check-all me-1"></i>Mark All as Read
                            </button>
                            <button type="submit" name="clear_all_alerts" class="btn btn-outline-danger" onclick="return confirm('Clear all alerts? This cannot be undone.')">
                                <i class="bi bi-trash me-1"></i>Clear All Alerts
                            </button>
                            <button type="submit" name="mark_read" class="btn btn-outline-success" onclick="return confirm('Mark selected alerts as read?')">
                                <i class="bi bi-check-all me-1"></i>Mark Selected as Read
                            </button>
                            <button type="submit" name="delete_alerts" class="btn btn-outline-danger" onclick="return confirm('Delete selected alerts? This cannot be undone.')">
                                <i class="bi bi-trash me-1"></i>Delete Selected
                            </button>
                        </div>
                    </div>
                
                    <?php if (empty($alerts)): ?>
                        <div class="alert alert-info">
                            No alerts found.
                        </div>
                    <?php else: ?>
                        <?php foreach ($alerts as $alert): ?>
                            <?php 
                                $isUnread = $alert['is_read'] == 0;
                                $isUrgent = strpos($alert['message'], 'URGENT') !== false;
                                $cardClass = $isUrgent ? 'alert-card urgent' : ($isUnread ? 'alert-card unread' : 'alert-card read');
                            ?>
                            <div class="<?= $cardClass ?>">
                                <div class="alert-header">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" name="alert_ids[]" value="<?= $alert['id'] ?>">
                                        <strong><?= htmlspecialchars($alert['message']) ?></strong>
                                    </div>
                                    <div>
                                        <?php if ($isUnread): ?>
                                            <span class="badge badge-unread">Unread</span>
                                        <?php endif; ?>
                                        <?php if ($isUrgent): ?>
                                            <span class="badge bg-danger">URGENT</span>
                                        <?php endif; ?>
                                    </div>
                                </div>
                                <div class="alert-body">
                                    <p><strong>Employee:</strong> <?= $alert['employee_name'] ? htmlspecialchars($alert['employee_name']) : 'N/A' ?></p>
                                    <p><strong>Details:</strong></p>
                                    <pre class="bg-light p-2 rounded"><?= htmlspecialchars($alert['device_info']) ?></pre>
                                </div>
                                <div class="alert-footer d-flex justify-content-between">
                                    <small class="text-muted">
                                        <i class="bi bi-clock me-1"></i>
                                        <?= date('M j, Y g:i A', strtotime($alert['timestamp'])) ?>
                                    </small>
                                    <small class="text-muted">Alert ID: <?= $alert['id'] ?></small>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </form>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html> 