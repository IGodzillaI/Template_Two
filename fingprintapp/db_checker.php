<?php
require 'db.php';

// Check database connection
if (!$conn) {
    die("Database connection failed");
}

// Get session_id table structure
$query = "DESCRIBE session_id";
$result = $conn->query($query);

if (!$result) {
    die("Error getting table structure: " . $conn->error);
}

echo "<h2>session_id Table Structure</h2>";
echo "<table border='1'>";
echo "<tr><th>Field</th><th>Type</th><th>Null</th><th>Key</th><th>Default</th><th>Extra</th></tr>";

while ($row = $result->fetch_assoc()) {
    echo "<tr>";
    echo "<td>" . $row['Field'] . "</td>";
    echo "<td>" . $row['Type'] . "</td>";
    echo "<td>" . $row['Null'] . "</td>";
    echo "<td>" . $row['Key'] . "</td>";
    echo "<td>" . $row['Default'] . "</td>";
    echo "<td>" . $row['Extra'] . "</td>";
    echo "</tr>";
}

echo "</table>";

// Check for existing session in table
echo "<h2>Session Check</h2>";
$query = "SELECT * FROM session_id LIMIT 5";
$result = $conn->query($query);

if (!$result) {
    die("Error checking sessions: " . $conn->error);
}

echo "Number of sessions: " . $result->num_rows . "<br>";

if ($result->num_rows > 0) {
    echo "<table border='1'>";
    echo "<tr>";
    $fields = $result->fetch_fields();
    foreach ($fields as $field) {
        echo "<th>" . $field->name . "</th>";
    }
    echo "</tr>";
    
    $result->data_seek(0);
    while ($row = $result->fetch_assoc()) {
        echo "<tr>";
        foreach ($row as $key => $value) {
            echo "<td>" . $value . "</td>";
        }
        echo "</tr>";
    }
    echo "</table>";
}

// Check for ON DUPLICATE KEY UPDATE functionality
echo "<h2>Test ON DUPLICATE KEY UPDATE</h2>";
$test_id = 9999;
$test_session = "test_session_" . time();

// First try to delete any existing test data
$stmt = $conn->prepare("DELETE FROM session_id WHERE user_id = ?");
$stmt->bind_param("i", $test_id);
$stmt->execute();

// Now try to insert the test data
$stmt = $conn->prepare("
    INSERT INTO session_id (user_id, session_id, last_activity) 
    VALUES (?, ?, NOW())
    ON DUPLICATE KEY UPDATE last_activity = NOW()
");
$stmt->bind_param("is", $test_id, $test_session);

if ($stmt->execute()) {
    echo "Test insertion successful!<br>";
    
    // Now try to update the same record
    $stmt->execute();
    echo "Test update successful!<br>";
    
    // Clean up after the test
    $stmt = $conn->prepare("DELETE FROM session_id WHERE user_id = ?");
    $stmt->bind_param("i", $test_id);
    $stmt->execute();
} else {
    echo "Test failed: " . $stmt->error . "<br>";
} 