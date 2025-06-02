<?php
session_start();
require_once 'db.php';
require_once 'license_verifier.php';

// For debugging
error_log("Activate license page loaded with type: " . ($_GET['type'] ?? 'none'));

$type = $_GET['type'] ?? '';
$message = '';
$success = false;

if (!in_array($type, ['admin', 'attendance'])) {
    die('Invalid type');
}

if ($type === 'attendance') {
    // Only allow activation via admin dashboard license
    $message = 'Attendance System activation is only possible via the Admin Dashboard license. Please activate the Admin Dashboard license first.';
    $success = false;
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Trim and sanitize license key input
    $license_key = isset($_POST['license_key']) ? trim($_POST['license_key']) : '';
    
    // Debug the submitted license key
    error_log("License key submitted: " . substr($license_key, 0, 5) . "..." . substr($license_key, -5));
    
    if (empty($license_key)) {
        $message = 'Please enter a valid license key';
        $success = false;
    } else {
        // Check if license is suspended
        $stmt = $conn->prepare("SELECT status FROM licenses WHERE license_key = ? AND type = 'admin'");
        $stmt->bind_param("s", $license_key);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            $license = $result->fetch_assoc();
            if ($license['status'] === 'suspended') {
                $message = 'This license has been suspended. Please contact the system administrator for more information.';
                $success = false;
            } else {
                $verifier = new LicenseVerifier($type);
                $result = $verifier->activateLicense($license_key);
                $message = $result['message'];
                $success = $result['success'];
                
                if ($success) {
                    // Redirect to appropriate page after successful activation
                    $redirect = $type === 'admin' ? 'admin.php' : 'attendance.php';
                    header("Location: $redirect");
                    exit();
                }
            }
        } else {
            $message = 'Invalid license key. Please check and try again.';
            $success = false;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Activate License</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f8f9fa;
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .activation-container {
            max-width: 500px;
            width: 100%;
            padding: 2rem;
        }
        .card {
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        .card-header {
            background-color: #f8f9fa;
            border-bottom: 1px solid #eee;
            padding: 1.5rem;
        }
        .form-control {
            padding: 0.75rem;
            font-size: 1.1rem;
        }
        .btn-primary {
            padding: 0.75rem;
            font-size: 1.1rem;
        }
        .help-text {
            font-size: 0.85rem;
            color: #6c757d;
            margin-top: 0.5rem;
        }
        .alert {
            margin-bottom: 1.5rem;
        }
        .alert i {
            margin-right: 0.5rem;
        }
    </style>
</head>
<body>
    <div class="activation-container">
        <div class="card">
            <div class="card-header text-center">
                <h3 class="mb-0">Activate <?php echo $type === 'admin' ? 'Admin Dashboard' : 'Attendance System'; ?></h3>
            </div>
            <div class="card-body">
                <?php if ($message): ?>
                    <div class="alert alert-<?php echo $success ? 'success' : 'danger'; ?> mb-4">
                        <i class="fa-solid fa-<?php echo $success ? 'check-circle' : 'exclamation-circle'; ?>"></i>
                        <?php echo htmlspecialchars($message); ?>
                    </div>
                <?php endif; ?>

                <?php if ($type === 'admin'): ?>
                <form method="POST" class="needs-validation" novalidate>
                    <div class="mb-4">
                        <label for="license_key" class="form-label">License Key</label>
                        <input type="text" class="form-control" id="license_key" name="license_key" 
                               required placeholder="Enter license key" autocomplete="off" spellcheck="false">
                        <div class="invalid-feedback">
                            Please enter the license key
                        </div>
                        <div class="help-text">
                            <i class="bi bi-info-circle"></i>
                            Copy the license key exactly as shown in the Developer Dashboard
                        </div>
                    </div>
                    <button type="submit" class="btn btn-primary w-100">
                        Activate License
                    </button>
                </form>
                <?php else: ?>
                <div class="alert alert-info">
                    <i class="fa-solid fa-info-circle"></i>
                    Attendance System activation is only possible via the Admin Dashboard license.<br>
                    Please activate the Admin Dashboard license first.
                </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Form validation
        (function () {
            'use strict'
            var forms = document.querySelectorAll('.needs-validation')
            Array.prototype.slice.call(forms).forEach(function (form) {
                form.addEventListener('submit', function (event) {
                    if (!form.checkValidity()) {
                        event.preventDefault()
                        event.stopPropagation()
                    }
                    form.classList.add('was-validated')
                }, false)
            })
        })()
        
        // License key formatting
        document.getElementById('license_key').addEventListener('input', function() {
            // Trim whitespace as the user types
            this.value = this.value.trim();
        });
    </script>
</body>
</html> 