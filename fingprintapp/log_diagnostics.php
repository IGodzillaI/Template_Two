<?php
/**
 * Geolocation Diagnostics Logger
 * This file receives and logs diagnostic information about geolocation issues
 */

// Allow CORS for AJAX requests
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Only process POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405); // Method Not Allowed
    echo json_encode(['error' => 'Only POST requests are allowed']);
    exit;
}

// Get JSON input
$input = file_get_contents('php://input');
$data = json_decode($input, true);

// Validate input
if (!$data || !isset($data['type']) || !isset($data['timestamp'])) {
    http_response_code(400); // Bad Request
    echo json_encode(['error' => 'Invalid diagnostic data format']);
    exit;
}

// Add server timestamp and client IP
$data['server_timestamp'] = date('Y-m-d H:i:s');
$data['client_ip'] = $_SERVER['REMOTE_ADDR'];

// Create logs directory if it doesn't exist
$logsDir = __DIR__ . '/logs';
if (!file_exists($logsDir)) {
    mkdir($logsDir, 0755, true);
}

// Create daily log file
$logFile = $logsDir . '/geolocation_' . date('Y-m-d') . '.log';

// Format log entry
$logEntry = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";

// Append to log file
if (file_put_contents($logFile, $logEntry, FILE_APPEND)) {
    http_response_code(200);
    echo json_encode(['success' => true, 'message' => 'Diagnostic data logged']);
} else {
    http_response_code(500); // Internal Server Error
    echo json_encode(['error' => 'Failed to write to log file']);
} 