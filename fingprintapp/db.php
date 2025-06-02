<?php
// Protection against multiple inclusion
if (!defined('DB_INCLUDED')) {
    define('DB_INCLUDED', true);

    // Database configuration
    $db_host = 'localhost';
    $db_user = 'root';
    $db_pass = '';
    $db_name = 'fingprintapp';

    // Global connection variable
    global $conn;
    $conn = null;

    /**
     * Create a new database connection
     * @return mysqli|null
     */
    function createConnection() {
        global $db_host, $db_user, $db_pass, $db_name;
        
        try {
            // Suppress warnings when connecting to database
            $connection = @new mysqli($db_host, $db_user, $db_pass, $db_name);
            
            if ($connection->connect_error) {
                error_log("Connection failed: " . $connection->connect_error);
                return null;
            }
            
            // Set charset to utf8mb4
            $connection->set_charset("utf8mb4");
            
            return $connection;
        } catch (Exception $e) {
            error_log("Connection error: " . $e->getMessage());
            return null;
        }
    }

    /**
     * Ensure database connection exists and is active
     * @param mysqli|null $connection Existing connection to check
     * @return mysqli|null
     */
    function ensureConnection($connection = null) {
        global $conn;
        
        // If no connection provided, use global connection
        if ($connection === null) {
            $connection = $conn;
        }
        
        // Check if connection exists and is alive
        if ($connection && $connection->ping()) {
            return $connection;
        }
        
        // Create new connection
        $new_connection = createConnection();
        
        // Update global connection
        $conn = $new_connection;
        
        return $new_connection;
    }

    // Initialize connection
    $conn = createConnection();

    // Handle connection error
    if (!$conn) {
        error_log("Failed to establish initial database connection");
    }

    // Register shutdown function to close connection
    register_shutdown_function(function() {
        global $conn;
        if ($conn) {
            $conn->close();
        }
    });

    // Set error handler
    set_error_handler(function($errno, $errstr, $errfile, $errline) {
        if (strpos($errstr, 'mysqli') !== false) {
            error_log("MySQL Error ($errno): $errstr in $errfile on line $errline");
        }
        return false;
    });

    // Set timezone
    date_default_timezone_set('Africa/Cairo');
}