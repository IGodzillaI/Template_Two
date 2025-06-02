<?php
session_start();
require 'db.php';
require 'theme_helper.php'; // Include theme helper

// Get theme color from cookie or database
$theme_color = getThemeColor($conn);

// Set security headers
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https: fonts.googleapis.com; font-src 'self' https: fonts.gstatic.com;");

$error = '';
$remembered_email = '';

// Check for remembered email from cookie
if (isset($_COOKIE['remembered_email'])) {
    $remembered_email = $_COOKIE['remembered_email'];
}

// Get company name for branding
$company_name = "Fingerprint Attendance";
$check_table = $conn->query("SHOW TABLES LIKE 'system_settings'");
if ($check_table->num_rows > 0) {
    $settings_query = $conn->query("SELECT setting_value FROM system_settings WHERE setting_key = 'company_name'");
    if ($settings_query && $settings_query->num_rows > 0) {
        $row = $settings_query->fetch_assoc();
        if (!empty($row['setting_value'])) {
            $company_name = $row['setting_value'];
        }
    }
}

// Check if the system is in maintenance mode
$maintenance_mode = false;
$maintenance_reason = 'System update in progress';

// Get maintenance mode status if system_settings table exists
if ($check_table->num_rows > 0) {
    $maintenance_query = $conn->query("SELECT setting_key, setting_value FROM system_settings WHERE setting_key IN ('maintenance_mode', 'maintenance_reason')");
    if ($maintenance_query && $maintenance_query->num_rows > 0) {
        while ($row = $maintenance_query->fetch_assoc()) {
            if ($row['setting_key'] == 'maintenance_mode') {
                $maintenance_mode = ($row['setting_value'] == '1');
            } else if ($row['setting_key'] == 'maintenance_reason') {
                $maintenance_reason = $row['setting_value'];
            }
        }
    }
}

// Handle error messages from redirects
if (isset($_GET['error'])) {
    $errorCode = $_GET['error'];

    switch ($errorCode) {
        case 'invalid_session':
            $error = "Session Expired, Please Login Again";
            break;
        case 'db_error':
            $error = "Database Error Occurred, Please Try Again";
            break;
        case 'no_session':
            $error = "You Are Not Logged In, Please Login First";
            break;
        case 'db_connection':
            $error = "Failed to Connect to Database, Please Try Again Later";
            break;
        case 'security_violation':
            if (isset($_GET['msg'])) {
                $error = urldecode($_GET['msg']);
            } else {
                $error = "Security violation detected. Your account has been locked for protection.";
            }
            break;
        default:
            $error = "An Unexpected Error Occurred, Please Try Again";
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // First check if maintenance mode is active
    if ($maintenance_mode) {
        $error = "System is currently under maintenance. Please try again later.";
    } else {
        $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_STRING);
        $password = filter_input(INPUT_POST, 'passcode', FILTER_SANITIZE_STRING);
        $remember_me = isset($_POST['remember_me']);

        if ($email && $password) {
            // Debug log
            error_log("Login attempt - Email: " . $email . ", Password length: " . strlen($password));
            
            $stmt = $conn->prepare("SELECT id, name, email FROM employees WHERE email = ? AND password = ?");
            $stmt->bind_param("ss", $email, $password);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows === 1) {
                $employee = $result->fetch_assoc();
                
                // Check if the account is already logged in on another device
                $active_session_stmt = $conn->prepare("SELECT id, device_info FROM session_id WHERE user_id = ? AND last_activity > DATE_SUB(NOW(), INTERVAL 10 MINUTE)");
                $active_session_stmt->bind_param("i", $employee['id']);
                $active_session_stmt->execute();
                $active_session_result = $active_session_stmt->get_result();
                
                if ($active_session_result->num_rows > 0) { 
                    // Account is already logged in on another device
                    $active_session = $active_session_result->fetch_assoc();
                    
                    // Get device information
                    $current_device = $_SERVER['HTTP_USER_AGENT'];
                    $stored_device = $active_session['device_info'];
                    
                    // If it's a different device, handle security measures
                    if ($stored_device !== $current_device) {
                        // Log the security event
                        error_log("Multiple device login detected for employee ID: " . $employee['id'] . ". Existing device: " . $stored_device . ", New device: " . $current_device);
                        
                        // Generate a new random password
                        $new_password = bin2hex(random_bytes(16)); // 16 character password
                        
                        // Update the password in the database
                        $update_pwd_stmt = $conn->prepare("UPDATE employees SET password = ? WHERE id = ?");
                        $update_pwd_stmt->bind_param("si", $new_password, $employee['id']);
                        $update_pwd_stmt->execute();
                        
                        // Delete all sessions for this user
                        $delete_sessions_stmt = $conn->prepare("DELETE FROM session_id WHERE user_id = ?");
                        $delete_sessions_stmt->bind_param("i", $employee['id']);
                        $delete_sessions_stmt->execute();
                        
                        // Set error message
                        $error = "Security alert: Your account was accessed from multiple devices. For security, your password has been reset please call your administrator to reset your password";
                        
                        // Create security alert record
                        $alert_msg = "Multiple device login detected. Password automatically reset. Previous device: " . $stored_device;
                        $security_alert_stmt = $conn->prepare("INSERT INTO security_alerts (employee_id, alert_message, severity, device_info) VALUES (?, ?, 'high', ?)");
                        $security_alert_stmt->bind_param("iss", $employee['id'], $alert_msg, $current_device);
                        $security_alert_stmt->execute();
                        
                        // Clear any existing session
                        session_unset();
                        session_destroy();
                    } else {
                        // Same device, proceed with login
                        handleSuccessfulLogin($employee, $conn, $session_id, $remember_me, $email);
                    }
                } else {
                    // No active session, proceed with login
                    handleSuccessfulLogin($employee, $conn, $session_id, $remember_me, $email);
                }
            } else {
                $error = "Invalid username or password";
            }
        } else {
            $error = "Email or Password is incorrect";
        }
    }
}

// Helper function to handle successful login
function handleSuccessfulLogin($employee, $conn, &$session_id, $remember_me, $email) {
    // Handle "Remember Me" checkbox
    if ($remember_me) {
        // Set cookie to expire in 30 days
        setcookie('remembered_email', $email, time() + (86400 * 30), "/");
    } else {
        // Clear the cookie if remember me is not checked
        setcookie('remembered_email', '', time() - 3600, "/");
    }

    // Clear any old sessions for this user first
    $clear_stmt = $conn->prepare("DELETE FROM session_id WHERE user_id = ?");
    $clear_stmt->bind_param("i", $employee['id']);
    $clear_stmt->execute();

    // Generate new session ID
    $session_id = bin2hex(random_bytes(16));

    // Store session in database with device info
    $device_info = $_SERVER['HTTP_USER_AGENT'];
    $stmt = $conn->prepare("INSERT INTO session_id (user_id, session_id, last_activity, device_info) VALUES (?, ?, NOW(), ?)");
    $stmt->bind_param("iss", $employee['id'], $session_id, $device_info);

    if ($stmt->execute()) {
        // Set session variables
        $_SESSION['employee_id'] = $employee['id'];
        $_SESSION['employee_name'] = $employee['name'];
        $_SESSION['session_id'] = $session_id;

        // Debug: Log successful login
        error_log("Login successful for employee: " . $employee['id'] . " with session: " . $session_id);

        // Redirect to attendance page
        header("Location: attendance.php");
        exit;
    } else {
        // Log SQL error
        error_log("Session creation failed: " . $stmt->error);
        $error = "Error creating session. Please try again.";
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Employee Login - <?= htmlspecialchars($company_name) ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            /* Theme color variables */
            <?= getThemeCSS($theme_color) ?>
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Poppins', sans-serif;
        }

        body {
            min-height: 100vh;
            background: var(--primary-gradient);
            position: relative;
            overflow: hidden;
        }

        /* Animated Background */
        .animated-bg {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            overflow: hidden;
            z-index: -1;
        }

        .animated-bg span {
            position: absolute;
            display: block;
            width: 20px;
            height: 20px;
            background: rgba(255, 255, 255, 0.1);
            animation: animate 25s linear infinite;
            bottom: -150px;
            border-radius: 50%;
        }

        .animated-bg span:nth-child(1) {
            left: 10%;
            width: 80px;
            height: 80px;
            animation-delay: 0s;
            animation-duration: 15s;
        }

        .animated-bg span:nth-child(2) {
            left: 20%;
            width: 60px;
            height: 60px;
            animation-delay: 2s;
            animation-duration: 12s;
        }

        .animated-bg span:nth-child(3) {
            left: 30%;
            width: 70px;
            height: 70px;
            animation-delay: 4s;
            animation-duration: 13s;
        }

        .animated-bg span:nth-child(4) {
            left: 80%;
            width: 50px;
            height: 50px;
            animation-delay: 0s;
            animation-duration: 18s;
        }

        .animated-bg span:nth-child(5) {
            left: 50%;
            width: 60px;
            height: 60px;
            animation-delay: 7s;
            animation-duration: 20s;
        }

        .animated-bg span:nth-child(6) {
            left: 70%;
            width: 110px;
            height: 110px;
            animation-delay: 3s;
            animation-duration: 12s;
        }

        .animated-bg span:nth-child(7) {
            left: 40%;
            width: 40px;
            height: 40px;
            animation-delay: 5s;
            animation-duration: 16s;
        }

        .animated-bg span:nth-child(8) {
            left: 90%;
            width: 90px;
            height: 90px;
            animation-delay: 2s;
            animation-duration: 17s;
        }

        @keyframes animate {
            0% {
                transform: translateY(0) rotate(0deg);
                opacity: 0.8;
            }

            100% {
                transform: translateY(-1200px) rotate(720deg);
                opacity: 0;
            }
        }

        .login-wrapper {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 2rem;
        }

        .login-container {
            width: 100%;
            max-width: 450px;
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 3rem 2.5rem;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
            transform: translateY(30px);
            opacity: 0;
            animation: fadeUp 0.8s forwards;
            position: relative;
            z-index: 1;
            overflow: hidden;
            border-top: 5px solid var(--primary-color);
        }

        /* Glowing Borders */
        .login-container::before {
            content: '';
            position: absolute;
            top: -2px;
            left: -2px;
            right: -2px;
            bottom: -2px;
            background: var(--primary-gradient);
            z-index: -1;
            border-radius: 22px;
            background-size: 400%;
            animation: glowing 20s linear infinite;
            opacity: 0.7;
        }

        @keyframes glowing {
            0% {
                background-position: 0 0;
            }

            50% {
                background-position: 400% 0;
            }

            100% {
                background-position: 0 0;
            }
        }

        @keyframes fadeUp {
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .logo-container {
            text-align: center;
            margin-bottom: 2.5rem;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% {
                transform: scale(1);
            }

            50% {
                transform: scale(1.03);
            }

            100% {
                transform: scale(1);
            }
        }

        .logo-container h2 {
            margin: 0;
            color: var(--primary-color);
            font-weight: 700;
            font-size: 2rem;
            letter-spacing: -0.5px;
            position: relative;
            display: inline-block;
        }

        .logo-container h2::after {
            content: '';
            position: absolute;
            bottom: -10px;
            left: 50%;
            transform: translateX(-50%);
            width: 50%;
            height: 3px;
            background: var(--primary-gradient);
            border-radius: 50px;
        }

        .form-label {
            font-weight: 500;
            color: #333;
            font-size: 0.95rem;
            margin-bottom: 0.5rem;
            display: block;
        }

        .form-control {
            border: none;
            background-color: rgba(240, 240, 240, 0.8);
            padding: 0.8rem 1.2rem;
            border-radius: 10px;
            font-size: 1rem;
            transition: all 0.3s ease;
            margin-bottom: 1rem;
            box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.1);
        }

        .form-control:focus {
            box-shadow: 0 0 0 3px rgba(var(--primary-color), 0.2);
            background-color: #fff;
        }

        .form-floating {
            position: relative;
            margin-bottom: 1.5rem;
        }

        .form-floating .form-control {
            padding: 1.2rem 1rem 0.2rem;
            height: 60px;
        }

        .form-floating label {
            position: absolute;
            top: 0;
            left: 0;
            height: 100%;
            padding: 1rem 1rem;
            pointer-events: none;
            border: 1px solid transparent;
            transform-origin: 0 0;
            transition: opacity .1s ease-in-out, transform .1s ease-in-out;
            color: #666;
        }

        .form-floating .form-control:focus~label,
        .form-floating .form-control:not(:placeholder-shown)~label {
            transform: scale(0.8) translateY(-0.5rem) translateX(0.1rem);
            color: var(--primary-color);
        }

        .login-btn {
            background: var(--primary-gradient);
            color: white;
            border: none;
            padding: 1rem;
            border-radius: 10px;
            font-weight: 600;
            font-size: 1.1rem;
            margin-top: 1rem;
            width: 100%;
            cursor: pointer;
            box-shadow: 0 4px 15px rgba(var(--primary-color), 0.4);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .login-btn:hover {
            box-shadow: 0 6px 18px rgba(var(--primary-color), 0.6);
            transform: translateY(-2px);
        }

        .login-btn:active {
            box-shadow: 0 2px 10px rgba(var(--primary-color), 0.4);
            transform: translateY(1px);
        }

        .login-btn::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 0%;
            height: 100%;
            background-color: rgba(255, 255, 255, 0.2);
            transition: width 0.4s ease;
            z-index: 1;
        }

        .login-btn:hover::after {
            width: 100%;
        }

        .login-btn .btn-content {
            position: relative;
            z-index: 2;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .back-btn {
            background-color: transparent;
            color: var(--primary-color);
            border: 2px solid var(--primary-color);
            padding: 0.9rem;
            border-radius: 10px;
            font-weight: 600;
            font-size: 1.1rem;
            margin-top: 1rem;
            width: 100%;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .back-btn:hover {
            background-color: var(--primary-color);
            color: white;
        }

        .back-btn::after {
            content: '';
            position: absolute;
            width: 100%;
            height: 100%;
            top: 0;
            left: -100%;
            background: linear-gradient(120deg,
                    transparent,
                    rgba(255, 255, 255, 0.3),
                    transparent);
            transition: all 0.5s;
        }

        .back-btn:hover::after {
            left: 100%;
        }

        .alert {
            border-radius: 10px;
            font-size: 0.95rem;
            animation: slideDown 0.4s forwards;
            transform: translateY(-20px);
            opacity: 0;
        }

        @keyframes slideDown {
            to {
                transform: translateY(0);
                opacity: 1;
            }
        }

        .password-wrapper {
            position: relative;
        }

        .password-toggle {
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            cursor: pointer;
            color: #666;
            font-size: 1.2rem;
            opacity: 0.7;
            transition: color 0.3s;
        }

        .password-toggle:hover {
            color: var(--primary-color);
            opacity: 1;
        }

        .input-icon {
            position: absolute;
            left: 15px;
            top: 50%;
            transform: translateY(-50%);
            color: #666;
            font-size: 1.2rem;
        }

        .input-with-icon {
            padding-left: 45px;
        }

        .form-element {
            position: relative;
            margin-bottom: 1.5rem;
        }

        .form-element label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
            color: #333;
            font-size: 0.95rem;
            transition: all 0.2s;
        }

        .input-highlight {
            position: absolute;
            bottom: 0;
            left: 0;
            height: 2px;
            width: 0;
            background: var(--primary-gradient);
            transition: width 0.3s ease;
        }
        
        /* Remember Me checkbox styling */
        .form-check-input {
            width: 1.2em;
            height: 1.2em;
            margin-top: 0.15em;
            background-color: rgba(240, 240, 240, 0.8);
            border: none;
            box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.1);
            cursor: pointer;
        }
        
        .form-check-input:checked {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }
        
        .form-check-label {
            color: #666;
            font-size: 0.95rem;
            cursor: pointer;
            transition: color 0.3s;
        }
        
        .form-check-input:checked ~ .form-check-label {
            color: var(--primary-color);
            font-weight: 500;
        }

        .alert-danger {
            background-color: #fee2e2;
            color: #b91c1c;
        }

        /* Security Alert Styling */
        .security-alert {
            background-color: #7f1d1d;
            color: #fff;
            border-left: 5px solid #f87171;
            padding: 15px 20px;
            position: relative;
            box-shadow: 0 6px 15px rgba(0, 0, 0, 0.2);
            animation: pulse-alert 2s infinite;
        }
        
        @keyframes pulse-alert {
            0% {
                box-shadow: 0 0 0 0 rgba(248, 113, 113, 0.7);
            }
            70% {
                box-shadow: 0 0 0 10px rgba(248, 113, 113, 0);
            }
            100% {
                box-shadow: 0 0 0 0 rgba(248, 113, 113, 0);
            }
        }
        
        .security-alert .btn-close {
            filter: invert(1) grayscale(100%) brightness(200%);
        }
        
        .security-alert .bi-shield-exclamation {
            font-size: 1.2rem;
        }
    </style>
</head>

<body>
    <!-- Animated Background -->
    <div class="animated-bg">
        <span></span>
        <span></span>
        <span></span>
        <span></span>
        <span></span>
        <span></span>
        <span></span>
        <span></span>
    </div>

    <div class="login-wrapper">
        <div class="login-container">
            <div class="logo-container">
                <h2><?= htmlspecialchars($company_name) ?></h2>
                <p class="mt-2 text-muted">Employee Access Portal</p>
            </div>

            <?php if ($error): ?>
                <div class="alert <?= (isset($_GET['error']) && $_GET['error'] === 'security_violation') ? 'alert-danger security-alert' : 'alert-danger' ?> alert-dismissible fade show">
                    <i class="bi <?= (isset($_GET['error']) && $_GET['error'] === 'security_violation') ? 'bi-shield-exclamation' : 'bi-exclamation-triangle-fill' ?> me-2"></i>
                    <?= htmlspecialchars($error) ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            <?php endif; ?>

            <?php if ($maintenance_mode): ?>
                <div class="alert alert-warning" role="alert">
                    <h4 class="alert-heading"><i class="bi bi-exclamation-triangle-fill me-2"></i> System Maintenance</h4>
                    <p><?= htmlspecialchars($maintenance_reason) ?></p>
                    <hr>
                    <p class="mb-0">Please try again later or contact an administrator for assistance.</p>
                </div>
            <?php endif; ?>

            <form method="POST" action="" class="needs-validation mt-4" novalidate>
                <div class="form-element">
                    <label for="email"><i class="bi bi-envelope-fill me-2"></i>Email Address</label>
                    <input type="email" class="form-control" id="email" name="email" placeholder="Enter your email" required value="<?= htmlspecialchars($remembered_email) ?>">
                    <div class="input-highlight"></div>
                    <div class="invalid-feedback">Please enter a valid email address</div>
                </div>

                <div class="form-element">
                    <label for="passcode"><i class="bi bi-shield-lock-fill me-2"></i>Passcode</label>
                    <div class="password-wrapper">
                        <input type="password" class="form-control" id="passcode" name="passcode" placeholder="Enter your passcode" required minlength="4" autocomplete="current-password">
                        <button type="button" class="password-toggle" id="togglePassword" aria-label="Toggle password visibility">
                            <i class="bi bi-eye"></i>
                        </button>
                    </div>
                    <div class="input-highlight"></div>
                    <div class="invalid-feedback">Passcode must be at least 4 characters</div>
                </div>

                <div class="form-check mb-3 mt-3">
                    <input type="checkbox" class="form-check-input" id="remember_me" name="remember_me" 
                           <?= isset($_COOKIE['remembered_email']) ? 'checked' : '' ?>>
                    <label class="form-check-label" for="remember_me">
                        <i class="bi bi-bookmark-check me-1"></i> Remember my email
                    </label>
                </div>

                <div class="mt-4">
                    <button type="submit" class="login-btn">
                        <span class="btn-content">
                            <i class="bi bi-box-arrow-in-right me-2"></i> Login
                        </span>
                    </button>
                    <a href="index.php" class="btn back-btn d-block text-center mt-3">
                        <i class="bi bi-house-door-fill me-2"></i> Back to Home
                    </a>
                </div>
            </form>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Form validation
        (function() {
            'use strict'

            // Add animation to form inputs
            const inputs = document.querySelectorAll('.form-control');

            inputs.forEach(input => {
                // Add focus animation
                input.addEventListener('focus', function() {
                    this.parentElement.querySelector('.input-highlight').style.width = '100%';
                    this.parentElement.querySelector('label').style.color = getComputedStyle(document.documentElement).getPropertyValue('--primary-color');
                });

                // Remove focus animation
                input.addEventListener('blur', function() {
                    this.parentElement.querySelector('.input-highlight').style.width = '0';
                    if (!this.value) {
                        this.parentElement.querySelector('label').style.color = '#333';
                    }
                });
            });

            // Password toggle
            const togglePassword = document.getElementById('togglePassword');
            const passwordInput = document.getElementById('passcode');

            togglePassword.addEventListener('click', function() {
                const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
                passwordInput.setAttribute('type', type);
                this.querySelector('i').classList.toggle('bi-eye');
                this.querySelector('i').classList.toggle('bi-eye-slash');
                
                // Ensure the password value is preserved
                const currentValue = passwordInput.value;
                passwordInput.value = currentValue;
            });

            // Form validation
            const forms = document.querySelectorAll('.needs-validation');

            Array.prototype.slice.call(forms).forEach(function(form) {
                form.addEventListener('submit', function(event) {
                    if (!form.checkValidity()) {
                        event.preventDefault();
                        event.stopPropagation();

                        // Add shake animation to invalid fields
                        const invalidInputs = form.querySelectorAll(':invalid');
                        invalidInputs.forEach(input => {
                            input.classList.add('animate__animated', 'animate__shakeX');
                            input.addEventListener('animationend', () => {
                                input.classList.remove('animate__animated', 'animate__shakeX');
                            });
                        });
                    } else {
                        // Add loading state to button
                        const submitBtn = form.querySelector('button[type="submit"]');
                        submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span> Logging in...';
                        submitBtn.disabled = true;
                    }

                    form.classList.add('was-validated');
                }, false);
            });
        })();
    </script>
</body>

</html>