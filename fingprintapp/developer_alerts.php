<?php
session_name('developer_session');
session_start();
require_once 'developer_db.php';
if (!isset($_SESSION['developer_id'])) {
    header('Location: developer_login.php');
    exit();
}
$alerts = [];
$res = $dev_conn->query("SELECT * FROM developer_alerts ORDER BY created_at DESC");
if ($res) {
    while ($row = $res->fetch_assoc()) {
        $alerts[] = $row;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Developer Alerts</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body { background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%); min-height: 100vh; }
        .container { max-width: 700px; margin: 40px auto; background: #fff; border-radius: 18px; box-shadow: 0 8px 32px rgba(0,0,0,0.13); padding: 2.5rem 2rem; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; }
        .header h2 { color: #6a11cb; font-weight: bold; }
        .btn-back { background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%); color: #fff; border-radius: 10px; }
        .alert-item { border-left: 5px solid #f59e42; padding: 1.2rem 1rem; margin-bottom: 1.2rem; border-radius: 10px; background: #f8f9fa; }
        .alert-item .title { font-weight: bold; font-size: 1.1rem; color: #ef4444; }
        .alert-item .date { font-size: 0.95rem; color: #888; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2><i class="fa-solid fa-bell me-2"></i>Developer Alerts</h2>
            <a href="developer_dashboard.php" class="btn btn-back"><i class="fa-solid fa-arrow-left me-1"></i>Back</a>
        </div>
        <?php if (empty($alerts)): ?>
            <div class="alert alert-info text-center">No developer alerts found.</div>
        <?php else: ?>
            <?php foreach($alerts as $alert): ?>
                <div class="alert-item">
                    <div class="title"><i class="fa-solid fa-circle-exclamation me-2"></i><?= htmlspecialchars($alert['message']) ?></div>
                    <div class="date"><i class="fa-regular fa-clock me-1"></i><?= htmlspecialchars($alert['created_at']) ?></div>
                </div>
            <?php endforeach; ?>
        <?php endif; ?>
    </div>
</body>
</html> 