<?php
// Utility script to check and reset admin user password
// This is for debugging purposes only, should be removed in production

require 'db.php';

// Simple security check - require a specific token in URL
if (!isset($_GET['token']) || $_GET['token'] !== 'debug_token_12345678') {
    die("Unauthorized access");
}

// Display admin users
echo "<h2>Admin Users</h2>";
$result = $conn->query("SELECT id, username FROM admin");

if ($result->num_rows > 0) {
    echo "<table border='1'><tr><th>ID</th><th>Username</th></tr>";
    while ($row = $result->fetch_assoc()) {
        echo "<tr><td>{$row['id']}</td><td>{$row['username']}</td></tr>";
    }
    echo "</table>";
} else {
    echo "<p>No Admin Users Found</p>";
}

// Process password reset if requested
if (isset($_POST['reset_password'])) {
    $admin_id = $_POST['admin_id'];
    $new_password = $_POST['new_password'];
    
    // Hash the password using PASSWORD_DEFAULT (bcrypt)
    $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
    
    // Update the admin record
    $stmt = $conn->prepare("UPDATE admin SET password = ? WHERE id = ?");
    $stmt->bind_param("si", $hashed_password, $admin_id);
    
    if ($stmt->execute()) {
        echo "<p style='color:green'>Password reset successfully!</p>";
    } else {
        echo "<p style='color:red'>Error resetting password: " . $stmt->error . "</p>";
    }
}

// Add a new admin if requested
if (isset($_POST['add_admin'])) {
    $username = $_POST['new_username'];
    $password = $_POST['admin_password'];
    
    // Hash the password using PASSWORD_DEFAULT (bcrypt)
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
    
    // Insert the new admin record
    $stmt = $conn->prepare("INSERT INTO admin (username, password) VALUES (?, ?)");
    $stmt->bind_param("ss", $username, $hashed_password);
    
    if ($stmt->execute()) {
        echo "<p style='color:green'>New admin added successfully!</p>";
    } else {
        echo "<p style='color:red'>Error adding admin: " . $stmt->error . "</p>";
    }
}

// Test password verification if requested
if (isset($_POST['test_verify'])) {
    $admin_id = $_POST['verify_admin_id'];
    $test_password = $_POST['test_password'];
    
    // Get the stored hash
    $stmt = $conn->prepare("SELECT password FROM admin WHERE id = ?");
    $stmt->bind_param("i", $admin_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 1) {
        $admin = $result->fetch_assoc();
        $hash = $admin['password'];
        
        echo "<p>Stored hash: " . htmlspecialchars($hash) . "</p>";
        echo "<p>Hash algorithm info: " . htmlspecialchars(password_get_info($hash)['algoName']) . "</p>";
        
        $verify_result = password_verify($test_password, $hash);
        echo "<p>Verification result for password '" . htmlspecialchars($test_password) . "': " . 
             ($verify_result ? "<span style='color:green'>SUCCESS</span>" : "<span style='color:red'>FAILED</span>") . "</p>";
    } else {
        echo "<p style='color:red'>Admin ID not found</p>";
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Admin Password Management</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .form-section { margin-bottom: 30px; border: 1px solid #ccc; padding: 15px; }
        input[type="text"], input[type="password"] { padding: 5px; margin: 5px 0; }
        button { padding: 5px 10px; background: #4CAF50; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Admin Password Management</h1>
    
    <div class="form-section">
        <h3>Reset Admin Password</h3>
        <form method="post">
            <label>Select Admin ID: </label>
            <select name="admin_id">
                <?php
                $result = $conn->query("SELECT id, username FROM admin");
                while ($row = $result->fetch_assoc()) {
                    echo "<option value='{$row['id']}'>{$row['id']} - {$row['username']}</option>";
                }
                ?>
            </select><br>
            <label>New Password: </label>
            <input type="password" name="new_password" required><br>
            <button type="submit" name="reset_password">Reset Password</button>
        </form>
    </div>
    
    <div class="form-section">
        <h3>Add New Admin</h3>
        <form method="post">
            <label>Username: </label>
            <input type="text" name="new_username" required><br>
            <label>Password: </label>
            <input type="password" name="admin_password" required><br>
            <button type="submit" name="add_admin">Add Admin</button>
        </form>
    </div>
    
    <div class="form-section">
        <h3>Test Password Verification</h3>
        <form method="post">
            <label>Select Admin ID: </label>
            <select name="verify_admin_id">
                <?php
                $result = $conn->query("SELECT id, username FROM admin");
                while ($row = $result->fetch_assoc()) {
                    echo "<option value='{$row['id']}'>{$row['id']} - {$row['username']}</option>";
                }
                ?>
            </select><br>
            <label>Test Password: </label>
            <input type="password" name="test_password" required><br>
            <button type="submit" name="test_verify">Test Verification</button>
        </form>
    </div>
</body>
</html> 