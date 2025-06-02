<?php
session_name('developer_session');
session_start();
require_once 'developer_db.php';
if (!isset($_SESSION['developer_id'])) {
    header('Location: developer_login.php');
    exit();
}
$success = $error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $license_key = trim($_POST['license_key'] ?? '');
    $type = trim($_POST['type'] ?? '');
    $start_date = trim($_POST['start_date'] ?? '');
    $end_date = trim($_POST['end_date'] ?? '');
    if ($license_key === '' || $type === '' || $start_date === '' || $end_date === '') {
        $error = 'All fields are required.';
    } else {
        $stmt = $dev_conn->prepare("INSERT INTO licenses (license_key, type, start_date, end_date, status, created_at) VALUES (?, ?, ?, ?, 'active', NOW())");
        $stmt->bind_param('ssss', $license_key, $type, $start_date, $end_date);
        if ($stmt->execute()) {
            $success = 'License added successfully!';
        } else {
            $error = 'Error: ' . $dev_conn->error;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Add License</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body { background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%); min-height: 100vh; }
        .container { max-width: 500px; margin: 40px auto; background: #fff; border-radius: 18px; box-shadow: 0 8px 32px rgba(0,0,0,0.13); padding: 2.5rem 2rem; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; }
        .header h2 { color: #6a11cb; font-weight: bold; }
        .btn-back { background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%); color: #fff; border-radius: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2><i class="fa-solid fa-plus me-2"></i>Add License</h2>
            <a href="developer_dashboard.php" class="btn btn-back"><i class="fa-solid fa-arrow-left me-1"></i>Back</a>
        </div>
        <?php if ($success): ?>
            <div class="alert alert-success"> <?= htmlspecialchars($success) ?> </div>
        <?php elseif ($error): ?>
            <div class="alert alert-danger"> <?= htmlspecialchars($error) ?> </div>
        <?php endif; ?>
        <form method="POST" autocomplete="off">
            <div class="mb-3">
                <label for="license_key" class="form-label">License Key</label>
                <div class="input-group">
                    <input type="text" class="form-control" id="license_key" name="license_key" required maxlength="19" pattern="[A-Za-z0-9\$&@\*\|]{4}-[A-Za-z0-9\$&@\*\|]{4}-[A-Za-z0-9\$&@\*\|]{4}-[A-Za-z0-9\$&@\*\|]{4}">
                    <button type="button" class="btn btn-secondary" id="generate_key"><i class="fa-solid fa-bolt"></i> Generate</button>
                </div>
            </div>
            <div class="mb-3">
                <label for="type" class="form-label">Type</label>
                <select class="form-select" id="type" name="type" required>
                    <option value="">Select type</option>
                    <option value="admin">Admin Dashboard</option>
                    <option value="attendance">Attendance System</option>
                </select>
            </div>
            <div class="mb-3">
                <label for="start_date" class="form-label">Start Date</label>
                <input type="date" class="form-control" id="start_date" name="start_date" required>
            </div>
            <div class="mb-3">
                <label for="end_date" class="form-label">End Date</label>
                <input type="date" class="form-control" id="end_date" name="end_date" required>
            </div>
            <button type="submit" class="btn btn-primary w-100"><i class="fa-solid fa-plus me-1"></i>Add License</button>
        </form>
    </div>
    <script>
    // Auto-insert dash after every 4 characters in License Key
    document.addEventListener('DOMContentLoaded', function() {
        const input = document.getElementById('license_key');
        const genBtn = document.getElementById('generate_key');
        input.addEventListener('input', function(e) {
            let value = input.value.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
            let formatted = '';
            for (let i = 0; i < value.length; i += 4) {
                if (formatted.length > 0) formatted += '-';
                formatted += value.substr(i, 4);
            }
            input.value = formatted;
        });
        genBtn.addEventListener('click', function() {
            function randomBlock() {
                let chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$&@*';
                let block = '';
                for (let i = 0; i < 4; i++) block += chars.charAt(Math.floor(Math.random() * chars.length));
                return block;
            }
            input.value = randomBlock() + '-' + randomBlock() + '-' + randomBlock() + '-' + randomBlock();
        });
    });
    </script>
</body>
</html> 