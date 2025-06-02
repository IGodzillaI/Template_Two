<?php
session_name('admin_session');
session_start();
require 'db.php';

// Verify admin session
if (!isset($_SESSION['is_admin']) || !isset($_SESSION['admin_cookie']) || !isset($_SESSION['admin_id'])) {
    session_unset();
    session_destroy();
    header("Location: admin_login.php");
    exit;
}

// Set security headers
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");

// Function to get all table names from database
function getTables($conn) {
    $tables = array();
    $result = $conn->query("SHOW TABLES");
    while ($row = $result->fetch_row()) {
        $tables[] = $row[0];
    }
    return $tables;
}

// Function to generate table structure
function getTableStructure($conn, $table) {
    $structure = "DROP TABLE IF EXISTS `{$table}`;\n";
    
    $result = $conn->query("SHOW CREATE TABLE `{$table}`");
    $row = $result->fetch_assoc();
    
    $structure .= $row['Create Table'] . ";\n\n";
    return $structure;
}

// Function to get table data as INSERT statements
function getTableData($conn, $table) {
    $data = "";
    $result = $conn->query("SELECT * FROM `{$table}`");
    
    if ($result->num_rows > 0) {
        // Get column names
        $columns = array();
        $columnTypes = array();
        $columnsResult = $conn->query("SHOW COLUMNS FROM `{$table}`");
        while ($column = $columnsResult->fetch_assoc()) {
            $columns[] = $column['Field'];
            // Check if column type contains text, blob, or binary to handle it properly
            if (strpos(strtolower($column['Type']), 'text') !== false || 
                strpos(strtolower($column['Type']), 'blob') !== false ||
                strpos(strtolower($column['Type']), 'binary') !== false) {
                $columnTypes[$column['Field']] = 'binary';
            } else {
                $columnTypes[$column['Field']] = 'normal';
            }
        }
        
        // Create INSERT statements in batches of 100 rows
        $batchSize = 100;
        $rowCount = 0;
        $batchInsert = "";
        $columnsString = "`" . implode("`, `", $columns) . "`";
        
        while ($row = $result->fetch_assoc()) {
            if ($rowCount % $batchSize === 0) {
                if ($rowCount > 0) {
                    $batchInsert .= ";\n";
                    $data .= $batchInsert;
                    $batchInsert = "";
                }
                $batchInsert = "INSERT INTO `{$table}` ({$columnsString}) VALUES\n";
            } else {
                $batchInsert .= ",\n";
            }
            
            $values = array();
            foreach ($columns as $column) {
                if ($row[$column] === NULL) {
                    $values[] = 'NULL';
                } else if ($columnTypes[$column] === 'binary') {
                    $values[] = "'" . $conn->real_escape_string($row[$column]) . "'";
                } else {
                    $values[] = "'" . $conn->real_escape_string($row[$column]) . "'";
                }
            }
            
            $batchInsert .= "(" . implode(", ", $values) . ")";
            $rowCount++;
        }
        
        if ($rowCount % $batchSize !== 0) {
            $batchInsert .= ";\n";
            $data .= $batchInsert;
        }
    }
    
    return $data . "\n";
}

try {
    // Generate backup filename with date and time
    $dbname = $conn->query("SELECT DATABASE()")->fetch_row()[0];
    $backupFilename = $dbname . '_backup_' . date('Y-m-d_H-i-s') . '.sql';
    
    // Set headers for file download
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $backupFilename . '"');
    header('Content-Transfer-Encoding: binary');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    
    // Output SQL file header with metadata
    echo "-- Database Backup for: {$dbname}\n";
    echo "-- Generated on: " . date('Y-m-d H:i:s') . "\n";
    echo "-- Server version: " . $conn->server_info . "\n\n";
    
    echo "SET FOREIGN_KEY_CHECKS=0;\n";
    echo "SET SQL_MODE = \"NO_AUTO_VALUE_ON_ZERO\";\n";
    echo "SET AUTOCOMMIT = 0;\n";
    echo "START TRANSACTION;\n";
    echo "SET time_zone = \"+00:00\";\n\n";
    
    // Get all tables
    $tables = getTables($conn);
    
    // Generate backup for each table
    foreach ($tables as $table) {
        echo "-- Table structure for table `{$table}`\n";
        echo getTableStructure($conn, $table);
        
        echo "-- Data for table `{$table}`\n";
        echo getTableData($conn, $table);
    }
    
    echo "SET FOREIGN_KEY_CHECKS=1;\n";
    echo "COMMIT;\n";
    
    // Log the backup action
    $admin_id = $_SESSION['admin_id'];
    $stmt = $conn->prepare("INSERT INTO admin_alerts (employee_id, message, device_info, is_read) VALUES (?, 'System backup generated and downloaded', 'Admin action from dashboard', 0)");
    $stmt->bind_param("i", $admin_id);
    $stmt->execute();
    
} catch (Exception $e) {
    header("Location: admin.php?error=backup_failed&message=" . urlencode($e->getMessage()));
    exit;
} 