<?php
session_name('developer_session');
session_start();
require_once 'developer_db.php';
if (!isset($_SESSION['developer_id'])) {
    header('Location: developer_login.php');
    exit();
}

// Handle delete action
if (isset($_POST['delete_license'])) {
    $license_key = $_POST['license_key'];
    $stmt = $dev_conn->prepare("DELETE FROM licenses WHERE license_key = ?");
    $stmt->bind_param("s", $license_key);
    if ($stmt->execute()) {
        $success_message = "License deleted successfully!";
    } else {
        $error_message = "Error deleting license: " . $dev_conn->error;
    }
}

// Handle suspend/activate action
if (isset($_POST['toggle_status'])) {
    $license_key = $_POST['license_key'];
    $new_status = $_POST['current_status'] === 'active' ? 'suspended' : 'active';
    $stmt = $dev_conn->prepare("UPDATE licenses SET status = ? WHERE license_key = ?");
    $stmt->bind_param("ss", $new_status, $license_key);
    if ($stmt->execute()) {
        $success_message = $new_status === 'suspended' ? "License suspended successfully!" : "License activated successfully!";
    } else {
        $error_message = "Error updating license status: " . $dev_conn->error;
    }
}

$licenses = [];
$res = $dev_conn->query("SELECT license_key, type, start_date, end_date, status, created_at FROM licenses ORDER BY created_at DESC");
if ($res) {
    while ($row = $res->fetch_assoc()) {
        $licenses[] = $row;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>All Licenses</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body { background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%); min-height: 100vh; }
        .container { max-width: 1200px; margin: 40px auto; background: #fff; border-radius: 18px; box-shadow: 0 8px 32px rgba(0,0,0,0.13); padding: 2.5rem 2rem; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; }
        .header h2 { color: #6a11cb; font-weight: bold; }
        .btn-back { background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%); color: #fff; border-radius: 10px; }
        .table thead { background: #6a11cb; color: #fff; }
        .badge-active { background: #10b981; }
        .badge-inactive, .badge-expired { background: #ef4444; }
        .action-buttons { white-space: nowrap; }
        .btn-action { padding: 0.25rem 0.5rem; font-size: 0.875rem; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2><i class="fa-solid fa-list me-2"></i>All Licenses</h2>
            <a href="developer_dashboard.php" class="btn btn-back"><i class="fa-solid fa-arrow-left me-1"></i>Back</a>
        </div>

        <?php if (isset($success_message)): ?>
            <div class="alert alert-success alert-dismissible fade show" role="alert">
                <?= htmlspecialchars($success_message) ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        <?php endif; ?>

        <?php if (isset($error_message)): ?>
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                <?= htmlspecialchars($error_message) ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        <?php endif; ?>

        <div class="table-responsive">
            <table class="table table-bordered table-hover align-middle">
                <thead>
                    <tr>
                        <th>License Key</th>
                        <th>Type</th>
                        <th>Start Date</th>
                        <th>End Date</th>
                        <th>Status</th>
                        <th>Created At</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($licenses)): ?>
                        <tr><td colspan="7" class="text-center">No licenses found.</td></tr>
                    <?php else: ?>
                        <?php foreach ($licenses as $lic): ?>
                        <tr>
                            <td><code><?= htmlspecialchars($lic['license_key']) ?></code></td>
                            <td><?= htmlspecialchars(ucfirst($lic['type'])) ?></td>
                            <td><?= htmlspecialchars($lic['start_date']) ?></td>
                            <td><?= htmlspecialchars($lic['end_date']) ?></td>
                            <td>
                                <?php if ($lic['status'] === 'active'): ?>
                                    <span class="badge badge-active">Active</span>
                                <?php elseif ($lic['status'] === 'suspended'): ?>
                                    <span class="badge badge-warning">Suspended</span>
                                <?php elseif ($lic['status'] === 'inactive'): ?>
                                    <span class="badge badge-inactive">Inactive</span>
                                <?php else: ?>
                                    <span class="badge badge-expired">Expired</span>
                                <?php endif; ?>
                            </td>
                            <td><?= htmlspecialchars($lic['created_at']) ?></td>
                            <td class="action-buttons">
                                <form method="POST" style="display: inline;" onsubmit="return confirm('Are you sure you want to ' + ('<?= $lic['status'] === 'active' ? 'suspend' : 'activate' ?>') + ' this license?');">
                                    <input type="hidden" name="license_key" value="<?= htmlspecialchars($lic['license_key']) ?>">
                                    <input type="hidden" name="current_status" value="<?= htmlspecialchars($lic['status']) ?>">
                                    <button type="submit" name="toggle_status" class="btn btn-warning btn-action">
                                        <i class="fa-solid fa-<?= $lic['status'] === 'active' ? 'pause' : 'play' ?>"></i>
                                        <?= $lic['status'] === 'active' ? 'Suspend' : 'Activate' ?>
                                    </button>
                                </form>
                                <form method="POST" style="display: inline;" onsubmit="return confirm('Are you sure you want to delete this license? This action cannot be undone.');">
                                    <input type="hidden" name="license_key" value="<?= htmlspecialchars($lic['license_key']) ?>">
                                    <button type="submit" name="delete_license" class="btn btn-danger btn-action">
                                        <i class="fa-solid fa-trash"></i> Delete
                                    </button>
                                </form>
                                <a href="edit_license.php?license_key=<?= urlencode($lic['license_key']) ?>" class="btn btn-info btn-action ms-1">
                                    <i class="fa-solid fa-pen-to-square"></i> Edit
                                </a>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html> 