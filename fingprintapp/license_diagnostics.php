<?php
session_name('developer_session');
session_start();
require_once 'developer_db.php';
if (!isset($_SESSION['developer_id'])) {
    header('Location: developer_login.php');
    exit();
}
// Diagnostics
$results = [];
// Table check
$table_exists = $dev_conn->query("SHOW TABLES LIKE 'licenses'")->num_rows > 0;
$results[] = [
    'test' => 'Licenses Table Exists',
    'status' => $table_exists ? 'success' : 'danger',
    'message' => $table_exists ? 'Licenses table exists.' : 'Licenses table does not exist!'
];
// Structure check
$missing = [];
if ($table_exists) {
    $required = ['id','license_key','type','start_date','end_date','status','created_at','updated_at'];
    $cols = [];
    $q = $dev_conn->query("SHOW COLUMNS FROM licenses");
    while($c = $q->fetch_assoc()) $cols[] = $c['Field'];
    foreach($required as $col) if (!in_array($col, $cols)) $missing[] = $col;
    $results[] = [
        'test' => 'Table Structure',
        'status' => empty($missing) ? 'success' : 'danger',
        'message' => empty($missing) ? 'All required columns exist.' : 'Missing: '.implode(', ',$missing)
    ];
}
// Expired licenses
$expired = 0;
if ($table_exists) {
    $r = $dev_conn->query("SELECT COUNT(*) as c FROM licenses WHERE status='active' AND end_date < NOW()");
    if ($r) $expired = $r->fetch_assoc()['c'];
    $results[] = [
        'test' => 'Expired Active Licenses',
        'status' => $expired > 0 ? 'warning' : 'success',
        'message' => $expired > 0 ? "$expired expired but still active licenses" : 'No expired active licenses.'
    ];
}
// Duplicate keys
$dupes = 0;
if ($table_exists) {
    $r = $dev_conn->query("SELECT license_key, COUNT(*) as c FROM licenses GROUP BY license_key HAVING c > 1");
    $dupes = $r ? $r->num_rows : 0;
    $results[] = [
        'test' => 'Duplicate License Keys',
        'status' => $dupes > 0 ? 'danger' : 'success',
        'message' => $dupes > 0 ? "$dupes duplicate license keys found" : 'No duplicate license keys.'
    ];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>License Diagnostics</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body { background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%); min-height: 100vh; }
        .container { max-width: 700px; margin: 40px auto; background: #fff; border-radius: 18px; box-shadow: 0 8px 32px rgba(0,0,0,0.13); padding: 2.5rem 2rem; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; }
        .header h2 { color: #6a11cb; font-weight: bold; }
        .btn-back { background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%); color: #fff; border-radius: 10px; }
        .diagnostic-item { border-left: 5px solid #eee; padding: 1.2rem 1rem; margin-bottom: 1.2rem; border-radius: 10px; background: #f8f9fa; }
        .diagnostic-item.success { border-color: #10b981; }
        .diagnostic-item.warning { border-color: #f59e42; }
        .diagnostic-item.danger { border-color: #ef4444; }
        .diagnostic-item .title { font-weight: bold; font-size: 1.1rem; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2><i class="fa-solid fa-magnifying-glass-chart me-2"></i>License Diagnostics</h2>
            <a href="developer_dashboard.php" class="btn btn-back"><i class="fa-solid fa-arrow-left me-1"></i>Back</a>
        </div>
        <?php foreach($results as $item): ?>
            <div class="diagnostic-item <?= $item['status'] ?>">
                <div class="title"><i class="fa-solid fa-circle me-2"></i><?= htmlspecialchars($item['test']) ?></div>
                <div><?= htmlspecialchars($item['message']) ?></div>
            </div>
        <?php endforeach; ?>
    </div>
</body>
</html> 