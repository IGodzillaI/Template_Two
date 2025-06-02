<?php
require 'db.php';
require 'developer_db.php';

// // Check if user is logged in as developer
// session_start();
// if (!isset($_SESSION['developer_id'])) {
//     header("Location: developer_login.php");
//     exit;
// }

// Function to get all tables from a database
function getAllTables($conn) {
    $tables = array();
    $result = $conn->query("SHOW TABLES");
    while ($row = $result->fetch_row()) {
        $tables[] = $row[0];
    }
    return $tables;
}

// Function to reset auto increment for a table
function resetAutoIncrement($conn, $table) {
    try {
        // Get the current max ID
        $result = $conn->query("SELECT MAX(id) as max_id FROM `$table`");
        $row = $result->fetch_assoc();
        $next_id = ($row['max_id'] ?? 0) + 1;
        
        // Reset the auto increment
        $conn->query("ALTER TABLE `$table` AUTO_INCREMENT = $next_id");
        return ["success" => true, "message" => "Reset AUTO_INCREMENT for table '$table' to $next_id"];
    } catch (Exception $e) {
        return ["success" => false, "message" => "Error resetting AUTO_INCREMENT for table '$table': " . $e->getMessage()];
    }
}

// Initialize response arrays
$main_db_results = [];
$dev_db_results = [];

// Process form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['reset_main_db'])) {
        // Reset main database tables
        $tables = getAllTables($conn);
        foreach ($tables as $table) {
            $main_db_results[$table] = resetAutoIncrement($conn, $table);
        }
    }
    
    if (isset($_POST['reset_dev_db'])) {
        // Reset developer database tables
        $tables = getAllTables($dev_conn);
        foreach ($tables as $table) {
            $dev_db_results[$table] = resetAutoIncrement($dev_conn, $table);
        }
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Auto Increment IDs</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #f8f9fa;
            padding: 20px;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
        }
        .card {
            margin-bottom: 20px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        .results {
            margin-top: 20px;
        }
        .alert {
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="text-center mb-4">Reset Auto Increment IDs</h1>
        
        <div class="card">
            <div class="card-body">
                <div class="alert alert-warning">
                    <strong>Warning!</strong> Resetting auto-increment values will affect the next ID assigned to new records.
                    Make sure you understand the implications before proceeding.
                </div>
                
                <form method="POST" class="mb-4">
                    <div class="d-grid gap-2">
                        <button type="submit" name="reset_main_db" class="btn btn-primary" 
                                onclick="return confirm('Are you sure you want to reset auto-increment IDs for all tables in the main database?')">
                            Reset Main Database Auto-Increment IDs
                        </button>
                        
                        <button type="submit" name="reset_dev_db" class="btn btn-secondary"
                                onclick="return confirm('Are you sure you want to reset auto-increment IDs for all tables in the developer database?')">
                            Reset Developer Database Auto-Increment IDs
                        </button>
                    </div>
                </form>
                
                <?php if (!empty($main_db_results)): ?>
                    <div class="results">
                        <h4>Main Database Results:</h4>
                        <?php foreach ($main_db_results as $table => $result): ?>
                            <div class="alert alert-<?php echo $result['success'] ? 'success' : 'danger'; ?>">
                                <?php echo $result['message']; ?>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
                
                <?php if (!empty($dev_db_results)): ?>
                    <div class="results">
                        <h4>Developer Database Results:</h4>
                        <?php foreach ($dev_db_results as $table => $result): ?>
                            <div class="alert alert-<?php echo $result['success'] ? 'success' : 'danger'; ?>">
                                <?php echo $result['message']; ?>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>
        
        <div class="text-center">
            <a href="developer_dashboard.php" class="btn btn-outline-secondary">Back to Dashboard</a>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html> 