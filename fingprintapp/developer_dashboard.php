<?php
session_name('developer_session');
session_start();
require_once 'developer_db.php';
if (!isset($_SESSION['developer_id'])) {
    header('Location: developer_login.php');
    exit();
}
$dev_name = $_SESSION['developer_name'] ?? 'Developer';
// License stats
$total = $active = $expired = 0;
$res = $dev_conn->query("SELECT COUNT(*) as c FROM licenses");
if ($res) $total = $res->fetch_assoc()['c'];
$res = $dev_conn->query("SELECT COUNT(*) as c FROM licenses WHERE status='active'");
if ($res) $active = $res->fetch_assoc()['c'];
$res = $dev_conn->query("SELECT COUNT(*) as c FROM licenses WHERE status='inactive' OR end_date < NOW()");
if ($res) $expired = $res->fetch_assoc()['c'];
if (isset($_GET['logout'])) {
    session_unset(); session_destroy(); header('Location: developer_login.php'); exit();
}
?>
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Developer Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body { background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%); min-height: 100vh; }
        .dashboard-container { max-width: 900px; margin: 40px auto; background: #fff; border-radius: 18px; box-shadow: 0 8px 32px rgba(0,0,0,0.13); padding: 2.5rem 2rem; }
        .dashboard-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; }
        .dashboard-header h2 { color: #6a11cb; font-weight: bold; }
        .logout-btn { background: linear-gradient(135deg, #ef4444 0%, #f59e42 100%); border: none; color: #fff; border-radius: 10px; padding: 8px 22px; font-size: 1.1rem; }
        .logout-btn:hover { background: linear-gradient(135deg, #f59e42 0%, #ef4444 100%); }
        .stats-cards { display: flex; gap: 1.5rem; margin-bottom: 2rem; flex-wrap: wrap; }
        .stat-card { flex: 1 1 200px; background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%); color: #fff; border-radius: 14px; padding: 1.5rem 1rem; text-align: center; box-shadow: 0 2px 8px rgba(106,17,203,0.08); }
        .stat-card h4 { font-size: 2.2rem; margin-bottom: 0.5rem; }
        .stat-card .desc { font-size: 1.1rem; opacity: 0.9; }
        .quick-actions { margin-top: 2rem; }
        .quick-actions .btn { font-size: 1.1rem; border-radius: 10px; margin-right: 10px; margin-bottom: 10px; }
        @media (max-width: 700px) { .dashboard-container { padding: 1rem; } .stats-cards { flex-direction: column; gap: 1rem; } }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <div class="dashboard-header">
            <h2><i class="fa-solid fa-gauge-high me-2"></i>Developer Dashboard</h2>
            <div>
                <span class="me-3 fw-bold text-primary"><i class="fa-solid fa-user me-1"></i><?= htmlspecialchars($dev_name) ?></span>
                <a href="?logout=1" class="logout-btn btn"><i class="fa-solid fa-arrow-right-from-bracket me-1"></i>Logout</a>
            </div>
        </div>
        <div class="stats-cards">
            <div class="stat-card">
                <h4><?= $total ?></h4>
                <div class="desc">Total Licenses</div>
            </div>
            <div class="stat-card">
                <h4><?= $active ?></h4>
                <div class="desc">Active Licenses</div>
            </div>
            <div class="stat-card">
                <h4><?= $expired ?></h4>
                <div class="desc">Expired Licenses</div>
            </div>
        </div>
        <div class="quick-actions">
            <a href="add_license.php" class="btn btn-primary"><i class="fa-solid fa-plus me-1"></i>Add License</a>
            <a href="license_diagnostics.php" class="btn btn-info"><i class="fa-solid fa-magnifying-glass-chart me-1"></i>License Diagnostics</a>
            <a href="all_licenses.php" class="btn btn-success"><i class="fa-solid fa-list me-1"></i>Show All Licenses</a>
            <a href="developer_alerts.php" class="btn btn-warning"><i class="fa-solid fa-bell me-1"></i>Developer Alerts</a>
        </div>
    </div>
</body>
</html> 