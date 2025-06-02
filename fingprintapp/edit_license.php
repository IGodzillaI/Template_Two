<?php
session_name('developer_session');
session_start();
require_once 'developer_db.php';
if (!isset($_SESSION['developer_id'])) {
    header('Location: developer_login.php');
    exit();
}

// Set your passcode here
$edit_passcode = '01098138064&Godzilla$Developer$1'; // Change this to your desired passcode

$license_key = $_GET['license_key'] ?? '';
$show_form = false;
$error = '';
$success = '';
$license = null;

if ($license_key === '') {
    $error = 'No license key provided.';
} else {
    // Check passcode
    if (isset($_POST['passcode'])) {
        if ($_POST['passcode'] === $edit_passcode) {
            $show_form = true;
        } else {
            $error = 'Incorrect passcode.';
        }
    } elseif (isset($_POST['update_license'])) {
        // Passcode already validated in hidden field
        if ($_POST['edit_passcode'] === $edit_passcode) {
            $show_form = true;
            // Update license
            $new_license_key = trim($_POST['new_license_key'] ?? '');
            $type = trim($_POST['type'] ?? '');
            $start_date = trim($_POST['start_date'] ?? '');
            $end_date = trim($_POST['end_date'] ?? '');
            $status = trim($_POST['status'] ?? '');
            $stmt = $dev_conn->prepare("UPDATE licenses SET license_key=?, type=?, start_date=?, end_date=?, status=? WHERE license_key=?");
            $stmt->bind_param('ssssss', $new_license_key, $type, $start_date, $end_date, $status, $license_key);
            if ($stmt->execute()) {
                $success = 'License updated successfully!';
                $license_key = $new_license_key;
            } else {
                $error = 'Error updating license: ' . $dev_conn->error;
            }
        } else {
            $error = 'Incorrect passcode.';
        }
    }
    // Fetch license details
    $stmt = $dev_conn->prepare("SELECT * FROM licenses WHERE license_key = ?");
    $stmt->bind_param('s', $license_key);
    $stmt->execute();
    $res = $stmt->get_result();
    $license = $res->fetch_assoc();
    if (!$license) {
        $error = 'License not found.';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit License</title>
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
            <h2><i class="fa-solid fa-pen-to-square me-2"></i>Edit License</h2>
            <a href="all_licenses.php" class="btn btn-back"><i class="fa-solid fa-arrow-left me-1"></i>Back</a>
        </div>
        <?php if ($error): ?>
            <div class="alert alert-danger"> <?= htmlspecialchars($error) ?> </div>
        <?php elseif ($success): ?>
            <div class="alert alert-success"> <?= htmlspecialchars($success) ?> </div>
        <?php endif; ?>
        <?php if (!$show_form && !$success && $license): ?>
            <form method="POST">
                <div class="mb-3">
                    <label for="passcode" class="form-label">Enter Passcode to Edit License</label>
                    <input type="password" class="form-control" id="passcode" name="passcode" required autofocus>
                </div>
                <button type="submit" class="btn btn-primary w-100">Verify Passcode</button>
            </form>
        <?php elseif ($show_form && $license): ?>
            <form method="POST">
                <input type="hidden" name="edit_passcode" value="<?= htmlspecialchars($edit_passcode) ?>">
                <div class="mb-3">
                    <label for="new_license_key" class="form-label">License Key</label>
                    <div class="input-group">
                        <input type="text" class="form-control" id="new_license_key" name="new_license_key" value="<?= htmlspecialchars($license['license_key']) ?>" required maxlength="19" pattern="[A-Za-z0-9\$&@\*\|]{4}-[A-Za-z0-9\$&@\*\|]{4}-[A-Za-z0-9\$&@\*\|]{4}-[A-Za-z0-9\$&@\*\|]{4}">
                        <button type="button" class="btn btn-secondary" id="generate_key"><i class="fa-solid fa-bolt"></i> Generate</button>
                    </div>
                </div>
                <div class="mb-3">
                    <label for="type" class="form-label">Type</label>
                    <select class="form-select" id="type" name="type" required>
                        <option value="admin" <?= $license['type'] === 'admin' ? 'selected' : '' ?>>Admin Dashboard</option>
                        <option value="attendance" <?= $license['type'] === 'attendance' ? 'selected' : '' ?>>Attendance System</option>
                    </select>
                </div>
                <div class="mb-3">
                    <label for="start_date" class="form-label">Start Date</label>
                    <input type="date" class="form-control" id="start_date" name="start_date" value="<?= htmlspecialchars($license['start_date']) ?>" >
                </div>
                <div class="mb-3">
                    <label for="end_date" class="form-label">End Date</label>
                    <input type="date" class="form-control" id="end_date" name="end_date" value="<?= htmlspecialchars($license['end_date']) ?>" >
                </div>
                <div class="mb-3">
                    <label for="status" class="form-label">Status</label>
                    <select class="form-select" id="status" name="status" required>
                        <option value="active" <?= $license['status'] === 'active' ? 'selected' : '' ?>>Active</option>
                        <option value="suspended" <?= $license['status'] === 'suspended' ? 'selected' : '' ?>>Suspended</option>
                        <option value="inactive" <?= $license['status'] === 'inactive' ? 'selected' : '' ?>>Inactive</option>
                        <option value="expired" <?= $license['status'] === 'expired' ? 'selected' : '' ?>>Expired</option>
                    </select>
                </div>
                <button type="submit" name="update_license" class="btn btn-success w-100">Save Changes</button>
            </form>
        <?php endif; ?>
    </div>
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        const input = document.getElementById('new_license_key');
        const genBtn = document.getElementById('generate_key');

        // Optional: Auto-format as user types (similar to add_license.php)
        input.addEventListener('input', function(e) {
            let value = input.value.replace(/[^A-Za-z0-9\$&@\*\|]/g, '').toUpperCase();
            let formatted = '';
            for (let i = 0; i < value.length; i += 4) {
                if (formatted.length > 0) formatted += '-';
                formatted += value.substr(i, 4);
            }
            input.value = formatted;
        });

        // Generate button functionality
        genBtn.addEventListener('click', function() {
            function randomBlock() {
                let chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$&@*'; // Added special characters based on pattern
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