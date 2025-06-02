<?php
require_once 'db.php';

class LicenseVerifier {
    private $conn;
    private $type;
    private $license_key;

    public function __construct($type) {
        $this->conn = ensureConnection();
        $this->type = 'admin'; // Always use 'admin' as type regardless of input
        $this->license_key = $this->getStoredLicenseKey();
    }

    private function getStoredLicenseKey() {
        // Get license key from configuration file or database
        $config_file = __DIR__ . '/license_config.php';
        if (file_exists($config_file)) {
            $config = include $config_file;
            return $config['license_key'] ?? null;
        }
        return null;
    }

    public function verifyLicense() {
        if (!$this->license_key) {
            return [
                'valid' => false,
                'message' => 'License key not found.'
            ];
        }

        // Check for valid admin license
        $sql = "SELECT * FROM licenses WHERE license_key = ? AND type = 'admin' AND status = 'active' AND end_date >= CURDATE()";
        $stmt = $this->conn->prepare($sql);
        $stmt->bind_param("s", $this->license_key);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            return [
                'valid' => false,
                'message' => 'Invalid license key or license has expired.'
            ];
        }

        $license = $result->fetch_assoc();
        $now = new DateTime();
        $end_date = new DateTime($license['end_date']);

        if ($now > $end_date) {
            $this->updateLicenseStatus($this->license_key, 'expired');
            return [
                'valid' => false,
                'message' => 'License has expired.'
            ];
        }

        return [
            'valid' => true,
            'message' => 'License is valid.',
            'end_date' => $license['end_date']
        ];
    }

    public function getLicenseStatus() {
        if (!$this->license_key) {
            return null;
        }

        $sql = "SELECT status FROM licenses WHERE license_key = ? AND type = 'admin'";
        $stmt = $this->conn->prepare($sql);
        $stmt->bind_param("s", $this->license_key);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            return null;
        }

        $license = $result->fetch_assoc();
        return $license['status'];
    }

    private function updateLicenseStatus($license_key, $status) {
        $sql = "UPDATE licenses SET status = ? WHERE license_key = ?";
        $stmt = $this->conn->prepare($sql);
        $stmt->bind_param("ss", $status, $license_key);
        $stmt->execute();
    }

    public function activateLicense($license_key) {
        // Clean and standardize the license key
        $license_key = trim($license_key);
        
        // Debug: Log the license key being checked
        error_log("Attempting to activate license key: " . $license_key);
        
        // Get all licenses from database and compare manually for maximum flexibility
        $stmt = $this->conn->prepare("SELECT * FROM licenses WHERE license_key = ?");
        $stmt->bind_param("s", $license_key);
        $stmt->execute();
        $result = $stmt->get_result();
        $found_license = false;
        $license = null;
        
        error_log("Checking " . $result->num_rows . " total licenses in database");
        
        // Loop through all licenses and compare using a less strict approach
        while ($row = $result->fetch_assoc()) {
            // Normalize both keys for comparison by removing spaces, dashes and making lowercase
            $db_key_normalized = strtolower(str_replace(['-', ' ', '_'], '', $row['license_key']));
            $input_key_normalized = strtolower(str_replace(['-', ' ', '_'], '', $license_key));
            
            error_log("Comparing normalized keys - DB: " . $db_key_normalized . " vs Input: " . $input_key_normalized);
            
            if ($db_key_normalized === $input_key_normalized) {
                $found_license = true;
                $license = $row;
                error_log("Match found! License ID: " . $row['id'] . ", Key: " . $row['license_key']);
                break;
            }
        }
        
        // License not found after checking all records
        if (!$found_license) {
            error_log("License key not found in database after checking all records");
            return ['success' => false, 'message' => 'License key not found in database. Please check and try again.'];
        }

        // Check if license is already activated elsewhere
        $activation_check = $this->conn->prepare("SELECT COUNT(*) as c FROM license_activations WHERE license_key = ?");
        $activation_check->bind_param("s", $license['license_key']);
        $activation_check->execute();
        $activation_result = $activation_check->get_result();
        $activation_count = $activation_result ? $activation_result->fetch_assoc()['c'] : 0;
        if ($activation_count > 0) {
            // Log alert for developer dashboard in developer_alerts table
            $alert_stmt = $this->conn->prepare("INSERT INTO developer_alerts (message, created_at) VALUES (?, NOW())");
            $alert_message = 'License key ' . $license['license_key'] . ' was attempted to be used for a second Admin Dashboard activation.';
            $alert_stmt->bind_param("s", $alert_message);
            $alert_stmt->execute();
            return ['success' => false, 'message' => 'This license key has already been used to activate another Admin Dashboard. Each license can only be used on one dashboard.'];
        }
        
        // STEP 2: License exists, now check if it meets all criteria
        error_log("License found: ID=" . $license['id'] . ", Type=" . $license['type'] . ", Status=" . $license['status']);
        
        // Check license type - always look for admin type
        if ($license['type'] !== 'admin') {
            error_log("License type mismatch. Expected: admin, Found: " . $license['type']);
            return ['success' => false, 'message' => 'This license is not for Admin Dashboard.'];
        }
        
        // Check license status
        if ($license['status'] !== 'active') {
            error_log("License not active. Current status: " . $license['status']);
            return ['success' => false, 'message' => 'This license is not active.'];
        }
        
        // Check expiration date
        $now = new DateTime();
        $end_date = new DateTime($license['end_date']);
        
        if ($now > $end_date) {
            $this->updateLicenseStatus($license['license_key'], 'expired');
            error_log("License expired on: " . $license['end_date']);
            return ['success' => false, 'message' => 'This license has expired.'];
        }
        
        // All checks passed, activate the license
        error_log("License validation successful. Activating license.");
        
        // Store the original license key from database in config file
        $config_data = "<?php\nreturn ['license_key' => '{$license['license_key']}'];\n";
        $config_file = __DIR__ . '/license_config.php';
        
        $write_result = @file_put_contents($config_file, $config_data);
        if ($write_result === false) {
            error_log("Failed to write license key to config file: " . $config_file);
            // Continue anyway since we only store the key for convenience
        }
        
        // Record this activation
        $this->recordActivation($license['license_key']);
        
        return ['success' => true, 'message' => 'License activated successfully.'];
    }
    
    private function recordActivation($license_key) {
        // Record this activation in the database
        $ip_address = $_SERVER['REMOTE_ADDR'];
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        
        $stmt = $this->conn->prepare("INSERT INTO license_activations (license_key, activation_date, ip_address, user_agent) 
                                     VALUES (?, NOW(), ?, ?)");
        if ($stmt) {
            $stmt->bind_param("sss", $license_key, $ip_address, $user_agent);
            $stmt->execute();
        }
    }
}

// Usage example:
// $verifier = new LicenseVerifier('admin');
// $result = $verifier->verifyLicense();
// if (!$result['valid']) {
//     die($result['message']);
// } 