<?php
session_name('admin_session'); // Give admin session a unique name
session_start();
require 'db.php';

// Check admin authentication
if (!isset($_SESSION['is_admin']) || !isset($_SESSION['admin_cookie'])) {
    header("Location: admin_login.php");
    exit;
}

// Validate employee ID
if (!isset($_POST['employee_id']) || !is_numeric($_POST['employee_id'])) {
    header("Location: admin.php?error=invalid_employee");
    exit;
}

$employee_id = intval($_POST['employee_id']);

// Ensure database connection
$conn = ensureConnection($conn);
if (!$conn) {
    header("Location: admin.php?error=db_connection");
    exit;
}

// Get employee data
$stmt = $conn->prepare("SELECT * FROM employees WHERE id = ?");
$stmt->bind_param("i", $employee_id);
$stmt->execute();
$result = $stmt->get_result();
$employee = $result->fetch_assoc();

if (!$employee) {
    header("Location: admin.php?error=employee_not_found");
    exit;
}

// Get break history for this employee
$history_stmt = $conn->prepare("
    SELECT 
        bs.id,
        bs.break_start,
        bs.scheduled_end,
        bs.actual_end,
        COALESCE(bs.break_type, 'lunch') AS break_type,
        TIMESTAMPDIFF(MINUTE, bs.break_start, COALESCE(bs.actual_end, NOW())) AS duration_minutes
    FROM 
        break_schedule bs
    WHERE 
        bs.employee_id = ?
    ORDER BY 
        bs.break_start DESC
");
$history_stmt->bind_param("i", $employee_id);
$history_stmt->execute();
$break_history = $history_stmt->get_result();

// Set headers for Excel download
$filename = "break_history_" . $employee['name'] . "_" . date('Y-m-d') . ".xls";
header("Content-Type: application/vnd.ms-excel");
header("Content-Disposition: attachment; filename=\"$filename\"");
header("Pragma: no-cache");
header("Expires: 0");

// Start the Excel file output with proper encoding
echo '<?xml version="1.0" encoding="UTF-8"?>';
echo '<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet" xmlns:x="urn:schemas-microsoft-com:office:excel" xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet" xmlns:html="http://www.w3.org/TR/REC-html40">';
echo '<Worksheet ss:Name="Break History">';
echo '<Table>';

// Add header row with styling
echo '<Row>
        <Cell><Data ss:Type="String">Date</Data></Cell>
        <Cell><Data ss:Type="String">Type</Data></Cell>
        <Cell><Data ss:Type="String">Start Time</Data></Cell>
        <Cell><Data ss:Type="String">End Time</Data></Cell>
        <Cell><Data ss:Type="String">Duration (Minutes)</Data></Cell>
        <Cell><Data ss:Type="String">Status</Data></Cell>
      </Row>';

// Add data rows
if ($break_history && $break_history->num_rows > 0) {
    while ($break = $break_history->fetch_assoc()) {
        $start_time = new DateTime($break['break_start']);
        $status = "Completed";
        
        if ($break['actual_end'] === NULL) {
            $end_time = "In Progress";
            $status = "Active";
        } else {
            $end_time = new DateTime($break['actual_end']);
            $end_time = $end_time->format('h:i:s A');
        }
        
        // Calculate if break ended early or late
        if ($break['actual_end'] !== NULL) {
            $actual_end = new DateTime($break['actual_end']);
            $scheduled_end = new DateTime($break['scheduled_end']);
            
            $diff = $actual_end->getTimestamp() - $scheduled_end->getTimestamp();
            if ($diff > 60) {
                $status = "Ended Late";
            } elseif ($diff < -60) {
                $status = "Ended Early";
            }
        }
        
        // Convert break type to English
        $break_type = ucfirst($break['break_type']);
        
        echo '<Row>
                <Cell><Data ss:Type="String">' . $start_time->format('Y-m-d') . '</Data></Cell>
                <Cell><Data ss:Type="String">' . $break_type . '</Data></Cell>
                <Cell><Data ss:Type="String">' . $start_time->format('h:i:s A') . '</Data></Cell>
                <Cell><Data ss:Type="String">' . $end_time . '</Data></Cell>
                <Cell><Data ss:Type="Number">' . $break['duration_minutes'] . '</Data></Cell>
                <Cell><Data ss:Type="String">' . $status . '</Data></Cell>
              </Row>';
    }
} else {
    echo '<Row>
            <Cell><Data ss:Type="String">No break history found</Data></Cell>
          </Row>';
}

// Close Excel file structure
echo '</Table>';
echo '</Worksheet>';
echo '</Workbook>';
exit;
?> 