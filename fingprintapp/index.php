<?php
require 'db.php';
require 'theme_helper.php'; // Include theme helper

// Get theme color from cookie or database
$theme_color = getThemeColor($conn);

// Set security headers
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:;");

// Get system name and other settings
$company_name = "Godzilla Fingprint Attendance";
$system_version = "1.8.4";

// Check if system_settings table exists and get values
$check_table = $conn->query("SHOW TABLES LIKE 'system_settings'");
if ($check_table->num_rows > 0) {
    $settings_query = $conn->query("SELECT setting_key, setting_value FROM system_settings WHERE setting_key IN ('company_name', 'system_version')");
    if ($settings_query && $settings_query->num_rows > 0) {
        while ($row = $settings_query->fetch_assoc()) {
            if ($row['setting_key'] == 'company_name' && !empty($row['setting_value'])) {
                $company_name = $row['setting_value'];
            } else if ($row['setting_key'] == 'system_version' && !empty($row['setting_value'])) {
                $system_version = $row['setting_value'];
            }
        }
    }
}

// Get employee count
$employee_count = 0;
$employee_query = $conn->query("SELECT COUNT(*) as count FROM employees");
if ($employee_query && $employee_row = $employee_query->fetch_assoc()) {
    $employee_count = $employee_row['count'];
}

// Get today's date
$today = date('l, F j, Y');
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($company_name) ?> - Home</title>
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

        .hero-section {
            background: var(--primary-gradient);
            color: white;
            padding: 80px 0;
            margin-bottom: 60px;
            box-shadow: 0 6px 15px rgba(0, 0, 0, 0.08);
        }

        .hero-title {
            font-size: 3rem;
            font-weight: 700;
            margin-bottom: 20px;
        }

        .hero-subtitle {
            font-size: 1.5rem;
            font-weight: 300;
            margin-bottom: 30px;
            opacity: 0.9;
        }

        .feature-card {
            border-radius: 10px;
            border: none;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            margin-bottom: 30px;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            height: 100%;
            border-top: 3px solid var(--primary-color);
        }

        .feature-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 15px rgba(0, 0, 0, 0.1);
        }

        .feature-icon {
            font-size: 2.5rem;
            margin-bottom: 15px;
            color: var(--primary-color);
        }

        .stat-card {
            background: white;
            border-radius: 10px;
            padding: 30px 20px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            margin-bottom: 30px;
            transition: all 0.3s ease;
            border-top: 3px solid var(--primary-color);
        }

        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 15px rgba(0, 0, 0, 0.1);
        }

        .stat-number {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 10px;
            color: var(--primary-color);
        }

        .stat-title {
            font-size: 1.1rem;
            color: #6c757d;
        }

        .cta-section {
            background-color: #f1f3f5;
            padding: 60px 0;
            margin: 60px 0;
            border-radius: 10px;
        }

        .footer {
            background-color: #343a40;
            color: white;
            padding: 40px 0;
            margin-top: 60px;
        }

        .footer-link {
            color: rgba(255, 255, 255, 0.7);
            text-decoration: none;
            transition: color 0.2s;
        }

        .footer-link:hover {
            color: white;
        }

        .custom-button {
            background: var(--primary-gradient);
            color: white;
            border: none;
            border-radius: 50px;
            padding: 12px 35px;
            font-weight: 600;
            letter-spacing: 0.5px;
            transition: all 0.3s ease;
        }

        .custom-button:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 15px rgba(0, 0, 0, 0.1);
            color: white;
        }

        .date-badge {
            background-color: rgba(255, 255, 255, 0.2);
            padding: 8px 16px;
            border-radius: 50px;
            font-weight: 500;
            font-size: 0.9rem;
            margin-bottom: 20px;
            display: inline-block;
        }

        @media (max-width: 768px) {
            .hero-title {
                font-size: 2rem;
            }

            .hero-subtitle {
                font-size: 1.2rem;
            }

            .hero-section {
                padding: 50px 0;
                margin-bottom: 40px;
            }

            .feature-card {
                margin-bottom: 20px;
            }
        }
    </style>
</head>

<body>
    <!-- Hero Section -->
    <section class="hero-section">
        <div class="container text-center">
            <div class="date-badge">
                <i class="bi bi-calendar-date me-2"></i><?= $today ?>
            </div>
            <h1 class="hero-title"><?= htmlspecialchars($company_name) ?></h1>
            <p class="hero-subtitle">Modern Attendance & Task Management System</p>
            <div class="d-flex justify-content-center gap-3">
                <a href="login.php" class="btn custom-button">
                    <i class="bi bi-fingerprint me-2"></i>Employee Login
                </a>

            </div>
        </div>
    </section>

    <!-- Features Section -->
    <section class="container mb-5">
        <div class="text-center mb-5">
            <h2>System Features</h2>
            <p class="text-muted">Our comprehensive attendance system offers powerful features for employees</p>
        </div>

        <div class="row">
            <div class="col-md-4 mb-4">
                <div class="card feature-card">
                    <div class="card-body text-center">
                        <div class="feature-icon">
                            <i class="bi bi-fingerprint"></i>
                        </div>
                        <h5 class="card-title">Fingerprint Check-in</h5>
                        <p class="card-text text-muted">Seamlessly check in and out with our advanced fingerprint recognition system.</p>
                    </div>
                </div>
            </div>

            <div class="col-md-4 mb-4">
                <div class="card feature-card">
                    <div class="card-body text-center">
                        <div class="feature-icon">
                            <i class="bi bi-list-check"></i>
                        </div>
                        <h5 class="card-title">Task Management</h5>
                        <p class="card-text text-muted">Track and update assigned tasks with priorities and deadlines.</p>
                    </div>
                </div>
            </div>

            <div class="col-md-4 mb-4">
                <div class="card feature-card">
                    <div class="card-body text-center">
                        <div class="feature-icon">
                            <i class="bi bi-graph-up"></i>
                        </div>
                        <h5 class="card-title">Performance Analytics</h5>
                        <p class="card-text text-muted">View detailed statistics and reports about your work performance.</p>
                    </div>
                </div>
            </div>

            <div class="col-md-4 mb-4">
                <div class="card feature-card">
                    <div class="card-body text-center">
                        <div class="feature-icon">
                            <i class="bi bi-cup-hot"></i>
                        </div>
                        <h5 class="card-title">Break Management</h5>
                        <p class="card-text text-muted">Record and track break times throughout your workday.</p>
                    </div>
                </div>
            </div>

            <div class="col-md-4 mb-4">
                <div class="card feature-card">
                    <div class="card-body text-center">
                        <div class="feature-icon">
                            <i class="bi bi-calendar-check"></i>
                        </div>
                        <h5 class="card-title">Attendance History</h5>
                        <p class="card-text text-muted">Access your complete attendance history and work patterns.</p>
                    </div>
                </div>
            </div>

            <div class="col-md-4 mb-4">
                <div class="card feature-card">
                    <div class="card-body text-center">
                        <div class="feature-icon">
                            <i class="bi bi-shield-check"></i>
                        </div>
                        <h5 class="card-title">Secure Access</h5>
                        <p class="card-text text-muted">Enterprise-grade security to protect your attendance data.</p>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- CTA Section -->
    <section class="cta-section">
        <div class="container text-center">
            <h2 class="mb-4">Ready to Start Your Day?</h2>
            <p class="lead mb-4">Login to your employee account to check in and manage your tasks.</p>
            <a href="login.php" class="btn custom-button btn-lg">
                <i class="bi bi-box-arrow-in-right me-2"></i>Login Now
            </a>
        </div>
    </section>

    <!-- Footer -->
    <footer class="footer">
        <div class="container">
            <div class="row">
                <div class="col-md-6">
                    <h5 class="mb-3"><?= htmlspecialchars($company_name) ?></h5>
                    <p class="mb-0">Version <?= htmlspecialchars($system_version) ?></p>
                    <p>Modern Fingerprint Attendance & Task Management System</p>
                </div>

                <div class="col-md-6 text-md-end">
                    <h5 class="mb-3">Quick Links</h5>
                    <ul class="list-unstyled">
                        <li><a href="login.php" class="footer-link">Employee Login</a></li>
                    </ul>
                </div>
            </div>

            <hr class="my-4" style="background-color: rgba(255, 255, 255, 0.2);">

            <div class="row">
                <div class="col-md-6">
                    <p class="mb-0">&copy; <?= date('Y') ?> <?= htmlspecialchars($company_name) ?>. All rights reserved.</p>
                </div>
                <div class="col-md-6 text-md-end">
                    <p class="mb-0">Today is <?= $today ?></p>
                </div>
            </div>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>

</html>