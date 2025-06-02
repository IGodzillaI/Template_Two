<?php
session_name('admin_session');
session_start();

// Enable error reporting
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once 'db.php';
require_once 'helpers.php';

// Ensure database connection
$conn = ensureConnection($conn);
if (!$conn) {
    die("Database connection failed");
}

// Security headers
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';");

// Verify admin session
if (!isset($_SESSION['is_admin']) || !isset($_SESSION['admin_cookie']) || $_SESSION['is_admin'] !== true) {
    error_log("Admin session check failed");
    $_SESSION['error_message'] = "Admin authentication required";
    header("Location: admin_login.php");
    exit();
}

// Verify admin session in database
$stmt = $conn->prepare("SELECT id FROM admin_sessions WHERE session_id = ?");
$stmt->bind_param("s", $_SESSION['admin_cookie']);
$stmt->execute();
if ($stmt->get_result()->num_rows === 0) {
    error_log("Admin database session invalid");
    session_destroy();
    header("Location: admin_login.php");
    exit();
}

// Get employee ID
$employee_id = filter_var($_GET['id'] ?? '', FILTER_SANITIZE_NUMBER_INT);
if (!$employee_id) {
    $_SESSION['error_message'] = "Invalid employee ID";
    header("Location: admin.php");
    exit();
}

// Get employee details
$stmt = $conn->prepare("
    SELECT e.*, eo.otp, eo.created_at as otp_created_at, eo.expires_at as otp_expires_at
    FROM employees e
    LEFT JOIN employee_otp eo ON e.id = eo.employee_id
    WHERE e.id = ?
");
$stmt->bind_param("i", $employee_id);
$stmt->execute();
$result = $stmt->get_result();
$employee = $result->fetch_assoc();

if (!$employee) {
    $_SESSION['error_message'] = "Employee not found";
    header("Location: admin.php");
    exit();
}

// Handle employee verification
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error = "Invalid request";
    } else {
        try {
            // Start transaction
            $conn->begin_transaction();
            
            // Update employee verification status
            $stmt = $conn->prepare("UPDATE employees SET admin_verified = 1 WHERE id = ?");
            $stmt->bind_param("i", $employee_id);
            $stmt->execute();
            
            $conn->commit();
            $_SESSION['success_message'] = "Employee verified successfully";
            header("Location: admin.php");
            exit();
        } catch (Exception $e) {
            $conn->rollback();
            $error = "Error verifying employee: " . $e->getMessage();
        }
    }
}

// Generate new CSRF token
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>View Employee</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Bootstrap Icons -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css">
    <style>
        body {
            background-color: #f8f9fa;
            min-height: 100vh;
            display: flex;
            align-items: center;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
        }
        .card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .card-header {
            background-color: #0d6efd;
            color: white;
            border-radius: 15px 15px 0 0 !important;
            padding: 20px;
        }
        .card-body {
            padding: 30px;
        }
        .btn {
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: 500;
        }
        .btn-primary {
            background-color: #0d6efd;
            border: none;
        }
        .btn-primary:hover {
            background-color: #0b5ed7;
        }
        .btn-secondary {
            background-color: #6c757d;
            border: none;
        }
        .btn-secondary:hover {
            background-color: #5c636a;
        }
        .alert {
            border-radius: 8px;
            padding: 15px 20px;
            margin-bottom: 20px;
        }
        .text-muted {
            font-size: 0.875rem;
        }
        .icon-title {
            margin-right: 10px;
        }
        .info-box {
            background-color: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="card-header">
                <h4 class="mb-0">
                    <i class="bi bi-person-fill icon-title"></i>
                    Employee Details
                </h4>
            </div>
            <div class="card-body">
                <?php if (isset($error)): ?>
                    <div class="alert alert-danger">
                        <i class="bi bi-exclamation-triangle-fill me-2"></i>
                        <?php echo htmlspecialchars($error); ?>
                    </div>
                <?php endif; ?>
                
                <div class="info-box">
                    <h5>Personal Information</h5>
                    <p><strong>Name:</strong> <?php echo htmlspecialchars($employee['name']); ?></p>
                    <p><strong>Email:</strong> <?php echo htmlspecialchars($employee['email']); ?></p>
                    <p><strong>Registration Date:</strong> <?php echo date('Y-m-d H:i', strtotime($employee['created_at'])); ?></p>
                </div>
                
                <div class="info-box">
                    <h5>Verification Status</h5>
                    <p>
                        <strong>Email Verification:</strong>
                        <?php if ($employee['is_verified']): ?>
                            <span class="badge bg-success">Verified</span>
                        <?php else: ?>
                            <span class="badge bg-warning">Pending</span>
                        <?php endif; ?>
                    </p>
                    <p>
                        <strong>Admin Verification:</strong>
                        <?php if ($employee['admin_verified']): ?>
                            <span class="badge bg-success">Verified</span>
                        <?php else: ?>
                            <span class="badge bg-warning">Pending</span>
                        <?php endif; ?>
                    </p>
                    <?php if ($employee['otp']): ?>
                        <p>
                            <strong>OTP Status:</strong>
                            <?php if (strtotime($employee['otp_expires_at']) > time()): ?>
                                <span class="badge bg-info">Active</span>
                            <?php else: ?>
                                <span class="badge bg-danger">Expired</span>
                            <?php endif; ?>
                        </p>
                    <?php endif; ?>
                </div>
                
                <?php if (!$employee['admin_verified']): ?>
                    <form method="POST" action="">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        
                        <div class="d-grid gap-2">
                            <button type="submit" class="btn btn-primary btn-lg">
                                <i class="bi bi-check-circle me-2"></i>
                                Verify Employee
                            </button>
                            <a href="admin.php" class="btn btn-secondary">
                                <i class="bi bi-arrow-left me-2"></i>
                                Back to Admin Panel
                            </a>
                        </div>
                    </form>
                <?php else: ?>
                    <div class="d-grid gap-2">
                        <a href="admin.php" class="btn btn-secondary">
                            <i class="bi bi-arrow-left me-2"></i>
                            Back to Admin Panel
                        </a>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
    
    <!-- Bootstrap Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html> 