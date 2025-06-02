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

// Get break statistics for this employee
$stats_stmt = $conn->prepare("
    SELECT 
        COUNT(*) AS total_breaks,
        SUM(CASE WHEN COALESCE(break_type, 'lunch') = 'lunch' THEN 1 ELSE 0 END) AS lunch_breaks,
        SUM(CASE WHEN COALESCE(break_type, 'lunch') = 'rest' THEN 1 ELSE 0 END) AS rest_breaks,
        SUM(TIMESTAMPDIFF(MINUTE, break_start, COALESCE(actual_end, NOW()))) AS total_minutes,
        AVG(TIMESTAMPDIFF(MINUTE, break_start, actual_end)) AS avg_duration,
        COUNT(CASE WHEN actual_end > scheduled_end THEN 1 END) AS late_returns,
        COUNT(CASE WHEN actual_end IS NOT NULL AND actual_end < scheduled_end THEN 1 END) AS early_returns,
        MAX(TIMESTAMPDIFF(MINUTE, break_start, actual_end)) AS longest_break,
        MIN(TIMESTAMPDIFF(MINUTE, break_start, actual_end)) AS shortest_break
    FROM 
        break_schedule
    WHERE 
        employee_id = ?
        AND break_start >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
");
$stats_stmt->bind_param("i", $employee_id);
$stats_stmt->execute();
$break_stats = $stats_stmt->get_result()->fetch_assoc();

// Get monthly breakdown of breaks
$monthly_stmt = $conn->prepare("
    SELECT 
        DATE_FORMAT(break_start, '%Y-%m') AS month,
        COUNT(*) AS total_breaks,
        SUM(CASE WHEN COALESCE(break_type, 'lunch') = 'lunch' THEN 1 ELSE 0 END) AS lunch_breaks,
        SUM(CASE WHEN COALESCE(break_type, 'lunch') = 'rest' THEN 1 ELSE 0 END) AS rest_breaks,
        SUM(TIMESTAMPDIFF(MINUTE, break_start, COALESCE(actual_end, NOW()))) AS total_minutes
    FROM 
        break_schedule
    WHERE 
        employee_id = ?
        AND break_start >= DATE_SUB(CURDATE(), INTERVAL 6 MONTH)
    GROUP BY 
        DATE_FORMAT(break_start, '%Y-%m')
    ORDER BY 
        month DESC
");
$monthly_stmt->bind_param("i", $employee_id);
$monthly_stmt->execute();
$monthly_stats = $monthly_stmt->get_result();

// Get daily breakdown for current month
$daily_stmt = $conn->prepare("
    SELECT 
        DATE(break_start) AS day,
        COUNT(*) AS daily_breaks,
        SUM(TIMESTAMPDIFF(MINUTE, break_start, COALESCE(actual_end, NOW()))) AS daily_minutes
    FROM 
        break_schedule
    WHERE 
        employee_id = ?
        AND MONTH(break_start) = MONTH(CURRENT_DATE())
        AND YEAR(break_start) = YEAR(CURRENT_DATE())
    GROUP BY 
        DATE(break_start)
    ORDER BY 
        day DESC
");
$daily_stmt->bind_param("i", $employee_id);
$daily_stmt->execute();
$daily_stats = $daily_stmt->get_result();

// Set headers for Excel download
$filename = "break_statistics_" . $employee['name'] . "_" . date('Y-m-d') . ".xls";
header("Content-Type: application/vnd.ms-excel");
header("Content-Disposition: attachment; filename=\"$filename\"");
header("Pragma: no-cache");
header("Expires: 0");

// Start the Excel file output with proper encoding
echo '<?xml version="1.0" encoding="UTF-8"?>';
echo '<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet" xmlns:x="urn:schemas-microsoft-com:office:excel" xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet" xmlns:html="http://www.w3.org/TR/REC-html40">';

// Summary worksheet
echo '<Worksheet ss:Name="Summary Statistics">';
echo '<Table>';

// Add employee information
echo '<Row>
        <Cell><Data ss:Type="String">Employee Name:</Data></Cell>
        <Cell><Data ss:Type="String">' . htmlspecialchars($employee['name']) . '</Data></Cell>
      </Row>';
echo '<Row>
        <Cell><Data ss:Type="String">Employee ID:</Data></Cell>
        <Cell><Data ss:Type="Number">' . $employee['id'] . '</Data></Cell>
      </Row>';
echo '<Row>
        <Cell><Data ss:Type="String">Report Generated:</Data></Cell>
        <Cell><Data ss:Type="String">' . date('Y-m-d H:i:s') . '</Data></Cell>
      </Row>';
echo '<Row><Cell><Data ss:Type="String"></Data></Cell></Row>';

// Add summary statistics header
echo '<Row>
        <Cell><Data ss:Type="String">Statistic</Data></Cell>
        <Cell><Data ss:Type="String">Value</Data></Cell>
      </Row>';

// Add summary statistics data
echo '<Row>
        <Cell><Data ss:Type="String">Total Breaks (Last 30 Days)</Data></Cell>
        <Cell><Data ss:Type="Number">' . $break_stats['total_breaks'] . '</Data></Cell>
      </Row>';
echo '<Row>
        <Cell><Data ss:Type="String">Lunch Breaks</Data></Cell>
        <Cell><Data ss:Type="Number">' . $break_stats['lunch_breaks'] . '</Data></Cell>
      </Row>';
echo '<Row>
        <Cell><Data ss:Type="String">Rest Breaks</Data></Cell>
        <Cell><Data ss:Type="Number">' . $break_stats['rest_breaks'] . '</Data></Cell>
      </Row>';
echo '<Row>
        <Cell><Data ss:Type="String">Total Minutes on Break</Data></Cell>
        <Cell><Data ss:Type="Number">' . ceil($break_stats['total_minutes']) . '</Data></Cell>
      </Row>';
echo '<Row>
        <Cell><Data ss:Type="String">Average Break Duration (Minutes)</Data></Cell>
        <Cell><Data ss:Type="Number">' . round($break_stats['avg_duration']) . '</Data></Cell>
      </Row>';
echo '<Row>
        <Cell><Data ss:Type="String">Late Returns from Break</Data></Cell>
        <Cell><Data ss:Type="Number">' . $break_stats['late_returns'] . '</Data></Cell>
      </Row>';
echo '<Row>
        <Cell><Data ss:Type="String">Early Returns from Break</Data></Cell>
        <Cell><Data ss:Type="Number">' . $break_stats['early_returns'] . '</Data></Cell>
      </Row>';
echo '<Row>
        <Cell><Data ss:Type="String">Longest Break (Minutes)</Data></Cell>
        <Cell><Data ss:Type="Number">' . $break_stats['longest_break'] . '</Data></Cell>
      </Row>';
echo '<Row>
        <Cell><Data ss:Type="String">Shortest Break (Minutes)</Data></Cell>
        <Cell><Data ss:Type="Number">' . $break_stats['shortest_break'] . '</Data></Cell>
      </Row>';

// Close summary worksheet
echo '</Table>';
echo '</Worksheet>';

// Monthly breakdown worksheet
echo '<Worksheet ss:Name="Monthly Breakdown">';
echo '<Table>';

// Add header row
echo '<Row>
        <Cell><Data ss:Type="String">Month</Data></Cell>
        <Cell><Data ss:Type="String">Total Breaks</Data></Cell>
        <Cell><Data ss:Type="String">Lunch Breaks</Data></Cell>
        <Cell><Data ss:Type="String">Rest Breaks</Data></Cell>
        <Cell><Data ss:Type="String">Total Minutes</Data></Cell>
        <Cell><Data ss:Type="String">Average Per Break (Min)</Data></Cell>
      </Row>';

// Add monthly breakdown data
if ($monthly_stats && $monthly_stats->num_rows > 0) {
    while ($month = $monthly_stats->fetch_assoc()) {
        $avg_per_break = $month['total_breaks'] > 0 ? round($month['total_minutes'] / $month['total_breaks']) : 0;
        
        // Format month as "Month Year"
        $formatted_month = date('F Y', strtotime($month['month'] . '-01'));
        
        echo '<Row>
                <Cell><Data ss:Type="String">' . $formatted_month . '</Data></Cell>
                <Cell><Data ss:Type="Number">' . $month['total_breaks'] . '</Data></Cell>
                <Cell><Data ss:Type="Number">' . $month['lunch_breaks'] . '</Data></Cell>
                <Cell><Data ss:Type="Number">' . $month['rest_breaks'] . '</Data></Cell>
                <Cell><Data ss:Type="Number">' . $month['total_minutes'] . '</Data></Cell>
                <Cell><Data ss:Type="Number">' . $avg_per_break . '</Data></Cell>
              </Row>';
    }
} else {
    echo '<Row>
            <Cell><Data ss:Type="String">No monthly data found</Data></Cell>
          </Row>';
}

// Close monthly breakdown worksheet
echo '</Table>';
echo '</Worksheet>';

// Daily breakdown worksheet
echo '<Worksheet ss:Name="Daily Breakdown (Current Month)">';
echo '<Table>';

// Add header row
echo '<Row>
        <Cell><Data ss:Type="String">Date</Data></Cell>
        <Cell><Data ss:Type="String">Number of Breaks</Data></Cell>
        <Cell><Data ss:Type="String">Total Minutes</Data></Cell>
        <Cell><Data ss:Type="String">Average Per Break (Min)</Data></Cell>
      </Row>';

// Add daily breakdown data
if ($daily_stats && $daily_stats->num_rows > 0) {
    while ($day = $daily_stats->fetch_assoc()) {
        $avg_per_break = $day['daily_breaks'] > 0 ? round($day['daily_minutes'] / $day['daily_breaks']) : 0;
        
        // Format date as "Weekday, Month Day Year"
        $formatted_date = date('l, F j, Y', strtotime($day['day']));
        
        echo '<Row>
                <Cell><Data ss:Type="String">' . $formatted_date . '</Data></Cell>
                <Cell><Data ss:Type="Number">' . $day['daily_breaks'] . '</Data></Cell>
                <Cell><Data ss:Type="Number">' . $day['daily_minutes'] . '</Data></Cell>
                <Cell><Data ss:Type="Number">' . $avg_per_break . '</Data></Cell>
              </Row>';
    }
} else {
    echo '<Row>
            <Cell><Data ss:Type="String">No daily data found for current month</Data></Cell>
          </Row>';
}

// Close daily breakdown worksheet
echo '</Table>';
echo '</Worksheet>';

// Close Excel file structure
echo '</Workbook>';
exit;
?> 