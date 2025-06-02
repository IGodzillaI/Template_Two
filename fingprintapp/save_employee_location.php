<?php
session_name('admin_session');
session_start();
require 'db.php';

header('Content-Type: application/json');

// Verify admin session
if (!isset($_SESSION['is_admin']) || !isset($_SESSION['admin_cookie']) || !isset($_SESSION['admin_id'])) {
    echo json_encode(['success' => false, 'message' => 'Unauthorized access.']);
    exit;
}

// Verify session in database
$admin_cookie = $_SESSION['admin_cookie'];
$admin_id = $_SESSION['admin_id'];
$stmt = $conn->prepare("SELECT 1 FROM admin_sessions WHERE session_id = ? AND admin_id = ? AND last_activity > DATE_SUB(NOW(), INTERVAL 5 MINUTE)");
$stmt->bind_param("si", $admin_cookie, $admin_id);
$stmt->execute();

if ($stmt->get_result()->num_rows === 0) {
    echo json_encode(['success' => false, 'message' => 'Session expired. Please login again.']);
    exit;
}

// Process POST request
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // Check if this is a request to set default location for all employees
    if (isset($_POST['set_default']) && $_POST['set_default'] === 'true') {
        $default_latitude = $_POST['default_latitude'] ?? null;
        $default_longitude = $_POST['default_longitude'] ?? null;
        $default_range = $_POST['default_range_meters'] ?? null;

        // Convert empty strings to null
        $default_latitude = ($default_latitude === '') ? null : floatval($default_latitude);
        $default_longitude = ($default_longitude === '') ? null : floatval($default_longitude);
        $default_range = ($default_range === '') ? null : intval($default_range);
        
         // Basic range validation
        if ($default_range !== null && $default_range < 0) {
            echo json_encode(['success' => false, 'message' => 'Default allowed range cannot be negative.']);
            exit;
        }

        try {
            // Update employees where location is currently NULL
            $stmt = $conn->prepare("UPDATE employees SET allowed_latitude = COALESCE(allowed_latitude, ?), allowed_longitude = COALESCE(allowed_longitude, ?), allowed_range_meters = COALESCE(allowed_range_meters, ?) WHERE allowed_latitude IS NULL OR allowed_longitude IS NULL OR allowed_range_meters IS NULL");

            // Bind parameters
            $stmt->bind_param("ddi", $default_latitude, $default_longitude, $default_range);

            if ($stmt->execute()) {
                $affected_rows = $stmt->affected_rows;
                 // Add record to admin_alerts
                $alert_message = "Default location settings applied to " . $affected_rows . " employees.";
                $alert_stmt = $conn->prepare("INSERT INTO admin_alerts (message, device_info, is_read) VALUES (?, 'Admin action (Default Location)', 0)");
                $alert_stmt->bind_param("s", $alert_message);
                $alert_stmt->execute();

                echo json_encode(['success' => true, 'message' => 'Default location settings applied to ' . $affected_rows . ' employees.']);
            } else {
                 throw new Exception('Database update failed: ' . $conn->error);
            }
        } catch (Exception $e) {
            error_log("Error setting default employee location: " . $e->getMessage());
             echo json_encode(['success' => false, 'message' => 'Error setting default location: ' . $e->getMessage()]);
        } finally {
             if ($stmt) $stmt->close();
             if ($conn) $conn->close();
        }
    } else { // Handle individual employee location update
        $employee_id = intval($_POST['employee_id'] ?? 0);
        $latitude = $_POST['allowed_latitude'] ?? null;
        $longitude = $_POST['allowed_longitude'] ?? null;
        $range = $_POST['allowed_range_meters'] ?? null;

        // Validate input (basic validation)
        if (!$employee_id) {
            echo json_encode(['success' => false, 'message' => 'Invalid employee ID.']);
            exit;
        }

        // Convert empty strings to null for database storage
        $latitude = ($latitude === '') ? null : floatval($latitude);
        $longitude = ($longitude === '') ? null : floatval($longitude);
        $range = ($range === '') ? null : intval($range);

         // Basic range validation
        if ($range !== null && $range < 0) {
            echo json_encode(['success' => false, 'message' => 'Allowed range cannot be negative.']);
            exit;
        }

        try {
            // Prepare the UPDATE statement
            $stmt = $conn->prepare("UPDATE employees SET allowed_latitude = ?, allowed_longitude = ?, allowed_range_meters = ? WHERE id = ?");

            // Determine parameter types (s for string, i for integer, d for double/float)
            $param_types = "ddii"; // Assuming latitude/longitude are double, range/id are integer

            // Execute the statement
            $stmt->bind_param($param_types, $latitude, $longitude, $range, $employee_id);

            if ($stmt->execute()) {
                // Add record to admin_alerts
                $alert_message = "Employee location settings updated for employee ID: " . $employee_id;
                $alert_stmt = $conn->prepare("INSERT INTO admin_alerts (employee_id, message, device_info, is_read) VALUES (?, ?, 'Admin action (Location Settings)', 0)");
                $alert_stmt->bind_param("is", $employee_id, $alert_message);
                $alert_stmt->execute();

                echo json_encode(['success' => true, 'message' => 'Location settings updated successfully.']);
            } else {
                throw new Exception('Database update failed: ' . $conn->error);
            }
        } catch (Exception $e) {
            error_log("Error saving employee location: " . $e->getMessage());
            echo json_encode(['success' => false, 'message' => 'Error saving location settings: ' . $e->getMessage()]);
        } finally {
             if ($stmt) $stmt->close();
             if ($conn) $conn->close();
        }
    }

} else {
    // Not a POST request
    echo json_encode(['success' => false, 'message' => 'Invalid request method.']);
}
?> 