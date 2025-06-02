<?php
session_name('admin_session');
session_start();

require 'db.php';
require 'theme_helper.php'; // Include theme helper

// Get theme color from cookie or database for admin interface
$theme_color = getAdminThemeColor($conn);

// Set security headers
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:;");

$error = '';

// Check if maintenance mode is enabled
$maintenance_mode = false;
$maintenance_reason = 'System maintenance in progress';
try {
    $maintenance_result = $conn->query("SELECT setting_key, setting_value FROM system_settings WHERE setting_key IN ('maintenance_mode', 'maintenance_reason')");
    if ($maintenance_result && $maintenance_result->num_rows > 0) {
        while ($row = $maintenance_result->fetch_assoc()) {
            if ($row['setting_key'] == 'maintenance_mode') {
                $maintenance_mode = ($row['setting_value'] == '1');
            } else if ($row['setting_key'] == 'maintenance_reason') {
                $maintenance_reason = $row['setting_value'];
            }
        }
    }
} catch (Exception $e) {
    // If there's an error, default to maintenance mode disabled
    $maintenance_mode = false;
}

// Check for remembered username in cookie
$remembered_username = '';
if (isset($_COOKIE['remembered_username'])) {
    $remembered_username = $_COOKIE['remembered_username'];
}

// If already logged in, redirect to admin panel
if (isset($_SESSION['is_admin'])) {
    header("Location: admin.php");
    exit;
}

// Get error message from session if exists
if (isset($_SESSION['login_error'])) {
    $error = $_SESSION['login_error'];
    unset($_SESSION['login_error']);
}

// Generate CSRF token
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verify CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $_SESSION['login_error'] = "Invalid form submission";
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    }

    if (empty($_POST['username']) || empty($_POST['password'])) {
        $_SESSION['login_error'] = "Please Provide both Username and Password";
    } else {
        $username = $_POST['username'];
        $password = $_POST['password'];

        // Set or clear the remember-me cookie
        if (isset($_POST['remember']) && $_POST['remember'] == 'on') {
            // Set cookie to expire in 30 days
            setcookie('remembered_username', $username, time() + (86400 * 30), "/");
        } else {
            // Clear any existing cookie
            if (isset($_COOKIE['remembered_username'])) {
                setcookie('remembered_username', '', time() - 3600, "/");
            }
        }

        // Add error logging to debug
        error_log("Login attempt for username: " . $username);

        // Check admin credentials from database
        $stmt = $conn->prepare("SELECT id, password FROM admin WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 1) {
            $admin = $result->fetch_assoc();
            error_log("Found user with ID: " . $admin['id']);

            // Debug password verification
            $hash = $admin['password'];
            error_log("Stored hash: " . $hash);
            $verify_result = password_verify($password, $hash);
            error_log("Password verification result: " . ($verify_result ? 'true' : 'false'));

            if ($verify_result) {
                // Check if there's already an active session
                $stmt = $conn->prepare("SELECT 1 FROM admin_sessions WHERE admin_id = ? AND last_activity > DATE_SUB(NOW(), INTERVAL 5 MINUTE)");
                $stmt->bind_param("i", $admin['id']);
                $stmt->execute();

                if ($stmt->get_result()->num_rows > 0) {
                    // Another session is active
                    $_SESSION['login_error'] = "Another admin session is currently active. Please try again later.";
                    logUnauthorizedAttempt($conn, $username, "Concurrent session attempt");
                } else {
                    // Clear old sessions
                    $stmt = $conn->prepare("DELETE FROM admin_sessions WHERE admin_id = ?");
                    $stmt->bind_param("i", $admin['id']);
                    $stmt->execute();

                    // Create new session
                    $_SESSION['is_admin'] = true;
                    $_SESSION['admin_id'] = $admin['id'];
                    $_SESSION['admin_cookie'] = bin2hex(random_bytes(16));

                    // Store session
                    $stmt = $conn->prepare("INSERT INTO admin_sessions (admin_id, session_id) VALUES (?, ?)");
                    $stmt->bind_param("is", $admin['id'], $_SESSION['admin_cookie']);
                    $stmt->execute();

                    header("Location: admin.php");
                    exit;
                }
            } else {
                logUnauthorizedAttempt($conn, $username, "Invalid Password");
                $_SESSION['login_error'] = "Invalid Username or Password";
            }
        } else {
            logUnauthorizedAttempt($conn, $username, "Invalid Username");
            $_SESSION['login_error'] = "Invalid Username or Password";
        }
    }
    // Redirect back to the login page after POST
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

function logUnauthorizedAttempt($conn, $username, $reason = '')
{
    $ip = $_SERVER['REMOTE_ADDR'];
    $user_agent = $_SERVER['HTTP_USER_AGENT'];
    $device_details = json_encode([
        'browser' => $user_agent,
        'os' => php_uname('s') . ' ' . php_uname('r'),
        'ip' => $ip,
        'reason' => $reason
    ]);

    $stmt = $conn->prepare("INSERT INTO admin_access_attempts (username, ip_address, user_agent, device_details) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("ssss", $username, $ip, $user_agent, $device_details);
    $stmt->execute();
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    <style>
        :root {
            /* Theme color variables */
            <?= getThemeCSS($theme_color) ?>
        }

        body {
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: var(--primary-gradient);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        .login-container {
            width: 100%;
            max-width: 450px;
            padding: 2.5rem;
            background: white;
            border-radius: 20px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
            position: relative;
            overflow: hidden;
            border-top: 5px solid var(--primary-color);
        }

        .login-container::before {
            content: "";
            position: absolute;
            top: -50px;
            left: -50px;
            width: 150px;
            height: 150px;
            background: var(--primary-gradient);
            border-radius: 50%;
            opacity: 0.1;
            z-index: 0;
        }

        .login-container::after {
            content: "";
            position: absolute;
            bottom: -80px;
            right: -50px;
            width: 180px;
            height: 180px;
            background: var(--primary-gradient);
            border-radius: 50%;
            opacity: 0.1;
            z-index: 0;
        }

        .login-header {
            text-align: center;
            margin-bottom: 2rem;
            position: relative;
            z-index: 1;
        }

        .login-header h2 {
            color: #333;
            font-weight: 700;
            margin-bottom: 10px;
            font-size: 2.2rem;
        }

        .login-header p {
            color: #666;
            font-size: 0.95rem;
        }

        .login-icon {
            font-size: 3rem;
            margin-bottom: 1rem;
            background: var(--primary-gradient);
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .form-floating {
            margin-bottom: 1.5rem;
            position: relative;
            z-index: 1;
        }

        .form-floating .form-control {
            height: 60px;
            border-radius: 15px;
            border: 2px solid #e1e1e1;
            padding: 1.2rem 1rem 0.5rem;
            font-size: 1rem;
            transition: all 0.3s ease;
        }

        .form-floating .form-control:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 0.25rem rgba(var(--primary-color), 0.1);
        }

        .form-floating label {
            padding: 1rem 1rem;
            color: #777;
        }

        .btn-login {
            width: 100%;
            padding: 0.8rem;
            border-radius: 15px;
            background: var(--primary-gradient);
            border: none;
            color: white;
            font-weight: 600;
            font-size: 1.1rem;
            margin-top: 1rem;
            box-shadow: 0 4px 15px rgba(var(--primary-color), 0.3);
            transition: all 0.3s ease;
            position: relative;
            z-index: 1;
            overflow: hidden;
        }

        .btn-login:hover {
            transform: translateY(-3px);
            box-shadow: 0 6px 20px rgba(var(--primary-color), 0.4);
        }

        .btn-login::after {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(135deg, var(--secondary-color) 0%, var(--primary-color) 100%);
            z-index: -1;
            transition: opacity 0.3s ease;
            opacity: 0;
        }

        .btn-login:hover::after {
            opacity: 1;
        }

        .alert {
            border-radius: 15px;
            font-size: 0.95rem;
            margin-bottom: 1.5rem;
            position: relative;
            z-index: 1;
        }

        .alert-danger {
            background-color: #fff1f2;
            border-color: #fecdd3;
            color: #be123c;
        }

        .alert-warning {
            background-color: #fffbeb;
            border-color: #fef3c7;
            color: #b45309;
        }

        .animate-character {
            text-transform: uppercase;
            background-image: var(--primary-gradient);
            background-size: 200% auto;
            color: #fff;
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: textclip 2s linear infinite;
            display: inline-block;
            font-size: 2.2rem;
        }

        @keyframes textclip {
            to {
                background-position: 200% center;
            }
        }

        .remember-me {
            display: flex;
            align-items: center;
            margin-bottom: 1.5rem;
            color: #666;
            font-size: 0.95rem;
        }

        .remember-me input {
            margin-right: 0.5rem;
        }

        .input-icon {
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--primary-color);
            font-size: 1.2rem;
            z-index: 10;
        }

        .password-toggle {
            cursor: pointer;
        }
    </style>
</head>

<body>
    <div class="login-container">
        <div class="login-header">
            <i class="bi bi-shield-lock login-icon"></i>
            <h2 class="animate-character">Admin Login</h2>
            <p>Please enter your credentials to access the admin dashboard</p>
        </div>

        <?php if (!empty($error)): ?>
            <div class="alert alert-danger alert-dismissible fade show">
                <i class="bi bi-exclamation-triangle-fill me-2"></i>
                <?= htmlspecialchars($error) ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        <?php endif; ?>

        <?php if ($maintenance_mode && !isset($_SESSION['is_admin'])): ?>
            <div class="alert alert-warning" role="alert">
                <h4 class="alert-heading"><i class="bi bi-exclamation-triangle-fill me-2"></i> System Maintenance</h4>
                <p><?= htmlspecialchars($maintenance_reason) ?></p>
                <hr>
                <p class="mb-0">Please try again later or contact an administrator for assistance.</p>
            </div>
        <?php endif; ?>

        <form method="POST" action="" id="loginForm" novalidate>
            <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
            <div class="form-floating mb-4 position-relative">
                <input type="text" class="form-control" id="username" name="username" placeholder="Username" required minlength="2" maxlength="50" pattern="[a-zA-Z0-9_]+" value="<?= htmlspecialchars($remembered_username) ?>" aria-label="Username">
                <label for="username"><i class="bi bi-person-fill me-2"></i>Username</label>
                <i class="bi bi-person-circle input-icon"></i>
                <div class="invalid-feedback">Please enter a valid username (2-50 characters, letters, numbers and underscore only)</div>
            </div>

            <div class="form-floating mb-4 position-relative">
                <input type="password" class="form-control" id="password" name="password" placeholder="Password" required minlength="4" aria-label="Password">
                <label for="password"><i class="bi bi-lock-fill me-2"></i>Password</label>
                <i class="bi bi-eye-slash input-icon password-toggle" id="togglePassword" role="button" aria-label="Toggle password visibility"></i>
                <div class="invalid-feedback">Password must be at least 4 characters long</div>
            </div>

            <div class="remember-me">
                <input type="checkbox" id="remember" name="remember" <?= !empty($remembered_username) ? 'checked' : '' ?>>
                <label for="remember">Remember me</label>
            </div>

            <button type="submit" class="btn btn-login">
                <i class="bi bi-box-arrow-in-right me-2"></i>Login
            </button>
        </form>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Password visibility toggle
        document.getElementById('togglePassword').addEventListener('click', function() {
            const passwordInput = document.getElementById('password');
            const icon = this;

            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                icon.classList.remove('bi-eye-slash');
                icon.classList.add('bi-eye');
                icon.setAttribute('aria-label', 'Hide password');
            } else {
                passwordInput.type = 'password';
                icon.classList.remove('bi-eye');
                icon.classList.add('bi-eye-slash');
                icon.setAttribute('aria-label', 'Show password');
            }
        });

        // Form validation
        document.getElementById('loginForm').addEventListener('submit', function(event) {
            if (!this.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            this.classList.add('was-validated');
        });
    </script>
</body>

</html>