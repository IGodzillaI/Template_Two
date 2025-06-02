<?php
session_name('admin_session'); // Use the same session name as admin.php
session_start();
require 'db.php';
require 'theme_helper.php'; // Include theme helper

// Get the admin theme color
$theme_color = getAdminThemeColor($conn);

// Set security headers
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:;");

// Verify admin session
if (!isset($_SESSION['is_admin']) || !isset($_SESSION['admin_cookie'])) {
    $_SESSION['error_message'] = "Admin session expired. Please login again.";
    header("Location: admin_login.php");
    exit;
}

// Verify session in database
$admin_cookie = $_SESSION['admin_cookie'];
$timeout = 600; // 10 minutes
$stmt = $conn->prepare("SELECT 1 FROM admin_sessions WHERE session_id = ? AND TIMESTAMPDIFF(SECOND, last_activity, NOW()) <= ?");
$stmt->bind_param("si", $admin_cookie, $timeout);
$stmt->execute();
if ($stmt->get_result()->num_rows === 0) {
    // Session expired or invalid
    session_unset();
    session_destroy();
    $_SESSION['error_message'] = "Session expired. Please login again.";
    header("Location: admin_login.php");
    exit;
}

// Update last activity
$stmt = $conn->prepare("UPDATE admin_sessions SET last_activity = NOW() WHERE session_id = ?");
$stmt->bind_param("s", $admin_cookie);
$stmt->execute();

$message = '';
$error = '';
$employee = null;

// Get employee ID from URL
$id = isset($_GET['id']) ? intval($_GET['id']) : 0;

if (!$id) {
    $_SESSION['error_message'] = "No employee ID provided.";
    header("Location: admin.php");
    exit;
}

// Get employee data
$stmt = $conn->prepare("SELECT * FROM employees WHERE id = ?");
$stmt->bind_param("i", $id);
$stmt->execute();
$result = $stmt->get_result();
$employee = $result->fetch_assoc();

if (!$employee) {
    $_SESSION['error_message'] = "Employee not found.";
    header("Location: admin.php");
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = trim($_POST['name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = trim($_POST['password'] ?? '');
    
    if ($name && $email) {
        // Validate email
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = "Please enter a valid email address";
        } else {
            try {
                // Check if email exists for other employees
                $stmt = $conn->prepare("SELECT 1 FROM employees WHERE email = ? AND id != ?");
                $stmt->bind_param("si", $email, $id);
                $stmt->execute();
                if ($stmt->get_result()->num_rows > 0) {
                    throw new Exception("This email is already used by another employee");
                }
                
                // Update employee
                if ($password) {
                    // Update with new password
                    $stmt = $conn->prepare("UPDATE employees SET name = ?, email = ?, password = ? WHERE id = ?");
                    $stmt->bind_param("sssi", $name, $email, $password, $id);
                } else {
                    // Update without changing password
                    $stmt = $conn->prepare("UPDATE employees SET name = ?, email = ? WHERE id = ?");
                    $stmt->bind_param("ssi", $name, $email, $id);
                }
                
                if ($stmt->execute()) {
                    $message = "Employee updated successfully";
                    // Refresh employee data
                    $stmt = $conn->prepare("SELECT * FROM employees WHERE id = ?");
                    $stmt->bind_param("i", $id);
                    $stmt->execute();
                    $employee = $stmt->get_result()->fetch_assoc();
                } else {
                    throw new Exception("Error updating employee");
                }
            } catch (Exception $e) {
                $error = $e->getMessage();
            }
        }
    } else {
        $error = "Please enter all required fields";
    }
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
    
    <title>Edit Employee</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Bootstrap Icons -->
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
        .card {
            border: none;
            border-radius: 12px;
            box-shadow: 0 6px 15px rgba(0, 0, 0, 0.08);
            overflow: hidden;
            margin-top: 30px;
            margin-bottom: 30px;
            max-width: 550px;
            margin-left: auto;
            margin-right: auto;
        }
        .card-header {
            background: var(--primary-gradient);
            color: white;
            border-bottom: none;
            padding: 15px 20px;
            position: relative;
        }
        .card-header h3 {
            margin-bottom: 0;
            font-weight: 600;
            font-size: 1.25rem;
        }
        .card-body {
            padding: 25px 20px;
        }
        .form-control {
            border-radius: 8px;
            padding: 8px 12px;
            border: 1px solid #dce7f1;
            margin-bottom: 10px;
            transition: all 0.3s;
            font-size: 0.95rem;
            height: auto;
        }
        .form-control:focus {
            box-shadow: 0 0 0 0.2rem rgba(37, 117, 252, 0.2);
            border-color: #2575fc;
        }
        .form-label {
            font-weight: 500;
            margin-bottom: 5px;
            color: #495057;
            font-size: 0.9rem;
        }
        .form-text {
            font-size: 0.8rem;
            margin-top: 3px;
        }
        .btn {
            padding: 8px 15px;
            font-size: 0.9rem;
            border-radius: 8px;
        }
        .btn-primary {
            background: var(--primary-gradient);
            border: none;
            font-weight: 500;
            letter-spacing: 0.3px;
            box-shadow: 0 3px 5px rgba(0, 0, 0, 0.15);
            transition: all 0.3s;
        }
        .btn-primary:hover {
            background: linear-gradient(135deg, var(--primary-dark) 0%, var(--secondary-color) 100%);
            transform: translateY(-1px);
            box-shadow: 0 4px 7px rgba(0, 0, 0, 0.2);
        }
        .btn-secondary {
            background-color: #e9ecef;
            border: none;
            color: #495057;
            font-weight: 500;
            transition: all 0.3s;
        }
        .btn-secondary:hover {
            background-color: #dee2e6;
            color: #212529;
        }
        .btn-outline-secondary {
            border-color: #dce7f1;
            color: #495057;
            font-size: 0.85rem;
        }
        .btn-outline-secondary:hover {
            background-color: #f8f9fa;
            color: #2575fc;
        }
        .alert {
            border-radius: 8px;
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
        .icon-large {
            font-size: 18px;
            vertical-align: middle;
            margin-right: 8px;
        }
        .required-field::after {
            content: "*";
            color: #dc3545;
            margin-left: 3px;
            font-size: 0.8rem;
        }
        .floating-card {
            animation: float 5s ease-in-out infinite;
        }
        @keyframes float {
            0% { transform: translateY(0px); }
            50% { transform: translateY(-8px); }
            100% { transform: translateY(0px); }
        }
        .back-link {
            display: inline-block;
            margin-top: 15px;
            color: #6a11cb;
            text-decoration: none;
            font-weight: 500;
            transition: all 0.3s;
            font-size: 0.9rem;
        }
        .back-link:hover {
            color: #2575fc;
            transform: translateX(-3px);
        }
        .back-link i {
            margin-right: 4px;
        }
        .input-group {
            margin-bottom: 10px;
        }
        .input-group .form-control {
            margin-bottom: 0;
        }
        .mb-3 {
            margin-bottom: 15px !important;
        }
        .mb-4 {
            margin-bottom: 20px !important;
        }
        
        /* Improved responsiveness */
        @media (max-width: 576px) {
            .card {
                margin-top: 15px;
                margin-bottom: 15px;
            }
            .card-body {
                padding: 20px 15px;
            }
            .form-control {
                padding: 7px 10px;
            }
            .btn {
                padding: 7px 12px;
                font-size: 0.85rem;
            }
            .card-header h3 {
                font-size: 1.1rem;
            }
            .icon-large {
                font-size: 16px;
                margin-right: 6px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-lg-8 col-md-10">
                <div class="card floating-card">
                    <div class="card-header">
                        <h3><i class="bi bi-pencil-square icon-large"></i>Edit Employee</h3>
                    </div>
                    <div class="card-body">
                        <?php if (!empty($error)): ?>
                            <div class="alert alert-danger" role="alert">
                                <i class="bi bi-exclamation-triangle-fill me-2"></i>
                                <?php echo htmlspecialchars($error); ?>
                            </div>
                        <?php endif; ?>
                        
                        <?php if (!empty($message)): ?>
                            <div class="alert alert-success" role="alert">
                                <i class="bi bi-check-circle-fill me-2"></i>
                                <?php echo htmlspecialchars($message); ?>
                            </div>
                        <?php endif; ?>
                        
                        <form method="POST" action="" class="compact-form">
                            <div class="mb-3">
                                <label for="name" class="form-label required-field">Employee Name</label>
                                <input type="text" class="form-control" id="name" name="name" 
                                       value="<?php echo htmlspecialchars($employee['name']); ?>" 
                                       placeholder="Enter employee name" required>
                            </div>
                            
                            <div class="mb-3">
                                <label for="email" class="form-label required-field">Email Address</label>
                                <input type="email" class="form-control" id="email" name="email" 
                                       value="<?php echo htmlspecialchars($employee['email']); ?>"
                                       placeholder="Enter email" required>
                            </div>
                            
                            <div class="mb-4">
                                <label for="password" class="form-label">New Password</label>
                                <div class="input-group">
                                    <input type="password" class="form-control" id="password" name="password" 
                                           placeholder="Leave empty to keep current">
                                    <button type="button" class="btn btn-outline-secondary" id="generatePasswordBtn">
                                        <i class="bi bi-magic"></i> Generate
                                    </button>
                                </div>
                                <div class="form-text text-muted">
                                    Leave empty to keep the current password.
                                </div>
                            </div>
                            
                            <div class="d-flex justify-content-between">
                                <a href="admin.php" class="btn btn-secondary">
                                    <i class="bi bi-arrow-left me-1"></i>Cancel
                                </a>
                                <button type="submit" class="btn btn-primary">
                                    <i class="bi bi-save me-1"></i>Update Employee
                                </button>
                            </div>
                        </form>
                        
                        <a href="admin.php" class="back-link">
                            <i class="bi bi-arrow-left"></i>Back to Admin Dashboard
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Random password generator
        document.getElementById('generatePasswordBtn').addEventListener('click', function() {
            const passwordField = document.getElementById('password');
            const length = 8; // Password length
            const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$*";
            let password = "";
            
            // Generate random password
            for (let i = 0; i < length; i++) {
                const randomIndex = Math.floor(Math.random() * charset.length);
                password += charset[randomIndex];
            }
            
            // Set the generated password to the input field
            passwordField.value = password;
            
            // Optionally show the password briefly
            passwordField.type = "text";
            setTimeout(function() {
                passwordField.type = "password";
            }, 2000); // Show for 2 seconds
        });
    </script>
</body>
</html> 