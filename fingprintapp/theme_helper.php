<?php
/**
 * Theme Helper - Manages theme settings across the application
 * 
 * This file:
 * 1. Checks for theme cookie
 * 2. Checks for theme in system_settings table
 * 3. Sets the appropriate theme
 * 4. Provides CSS variables for both themes
 */

if (!function_exists('getThemeColor')) {
    /**
     * Get the current theme color from cookies or database for employee interface
     * 
     * @param object $conn Database connection
     * @return string 'purple' or 'red'
     */
    function getThemeColor($conn) {
        return getThemeColorInternal($conn, 'employee_theme_color');
    }
}

if (!function_exists('getAdminThemeColor')) {
    /**
     * Get the current theme color from cookies or database for admin interface
     * 
     * @param object $conn Database connection
     * @return string 'purple' or 'red'
     */
    function getAdminThemeColor($conn) {
        return getThemeColorInternal($conn, 'admin_theme_color');
    }
}

if (!function_exists('getThemeColorInternal')) {
    /**
     * Internal function to get theme color
     * 
     * @param object $conn Database connection
     * @param string $cookie_name Cookie name to use
     * @return string 'purple' or 'red'
     */
    function getThemeColorInternal($conn, $cookie_name) {
        // Default theme
        $theme_color = 'purple';
        
        // Check if theme cookie exists
        if (isset($_COOKIE[$cookie_name]) && in_array($_COOKIE[$cookie_name], ['purple', 'red'])) {
            $theme_color = $_COOKIE[$cookie_name];
        } else {
            // Check database if no cookie exists
            if ($conn) {
                $check_table = $conn->query("SHOW TABLES LIKE 'system_settings'");
                
                if ($check_table && $check_table->num_rows > 0) {
                    $db_setting_key = str_replace('_theme_color', '', $cookie_name) . '_theme_color';
                    $theme_query = $conn->query("SELECT setting_value FROM system_settings WHERE setting_key = '$db_setting_key'");
                    
                    if ($theme_query && $theme_query->num_rows > 0) {
                        $row = $theme_query->fetch_assoc();
                        if (in_array($row['setting_value'], ['purple', 'red'])) {
                            $theme_color = $row['setting_value'];
                            
                            // Set cookie to match database value (30 day expiry)
                            setcookie($cookie_name, $theme_color, time() + (86400 * 30), "/");
                        }
                    }
                }
            }
        }
        
        return $theme_color;
    }
}

if (!function_exists('setThemeColor')) {
    /**
     * Set the theme color in cookies and optionally database for employee interface
     * 
     * @param string $theme_color 'purple' or 'red'
     * @param object $conn Database connection (optional)
     * @return bool Success status
     */
    function setThemeColor($theme_color, $conn = null) {
        return setThemeColorInternal($theme_color, $conn, 'employee_theme_color', 'employee_theme_color');
    }
}

if (!function_exists('setAdminThemeColor')) {
    /**
     * Set the theme color in cookies and optionally database for admin interface
     * 
     * @param string $theme_color 'purple' or 'red'
     * @param object $conn Database connection (optional)
     * @return bool Success status
     */
    function setAdminThemeColor($theme_color, $conn = null) {
        return setThemeColorInternal($theme_color, $conn, 'admin_theme_color', 'admin_theme_color');
    }
}

if (!function_exists('setThemeColorInternal')) {
    /**
     * Internal function to set theme color
     * 
     * @param string $theme_color 'purple' or 'red'
     * @param object $conn Database connection (optional)
     * @param string $cookie_name Cookie name to use
     * @param string $db_setting_key Database setting key to use
     * @return bool Success status
     */
    function setThemeColorInternal($theme_color, $conn = null, $cookie_name = 'employee_theme_color', $db_setting_key = 'employee_theme_color') {
        if (!in_array($theme_color, ['purple', 'red'])) {
            return false;
        }
        
        // Set cookie (30 day expiry)
        setcookie($cookie_name, $theme_color, time() + (86400 * 30), "/");
        
        // Update database if connection provided
        if ($conn) {
            $check_table = $conn->query("SHOW TABLES LIKE 'system_settings'");
            
            if ($check_table && $check_table->num_rows > 0) {
                $check_theme = $conn->query("SELECT 1 FROM system_settings WHERE setting_key = '$db_setting_key'");
                
                if ($check_theme && $check_theme->num_rows > 0) {
                    // Update existing setting
                    $stmt = $conn->prepare("UPDATE system_settings SET setting_value = ?, updated_at = NOW() WHERE setting_key = ?");
                    $stmt->bind_param("ss", $theme_color, $db_setting_key);
                    $stmt->execute();
                } else {
                    // Create new setting
                    $stmt = $conn->prepare("INSERT INTO system_settings (setting_key, setting_value, created_at, updated_at) VALUES (?, ?, NOW(), NOW())");
                    $stmt->bind_param("ss", $db_setting_key, $theme_color);
                    $stmt->execute();
                }
            }
        }
        
        return true;
    }
}

if (!function_exists('getThemeCSS')) {
    /**
     * Get CSS variables for the current theme
     * 
     * @param string $theme_color 'purple' or 'red'
     * @return string CSS variables
     */
    function getThemeCSS($theme_color) {
        if ($theme_color === 'red') {
            return <<<CSS
            --primary-color: #cb1111;
            --secondary-color: #fc2525;
            --primary-gradient: linear-gradient(135deg, #cb1111 0%, #fc2525 100%);
            --primary-dark: #9e0e0e;
            --primary-light: #ff5757;
CSS;
        } else {
            return <<<CSS
            --primary-color: #6a11cb;
            --secondary-color: #2575fc;
            --primary-gradient: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%);
            --primary-dark: #5a0cb6;
            --primary-light: #4285f4;
CSS;
        }
    }
} 