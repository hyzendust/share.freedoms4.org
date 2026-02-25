<?php
// -------------------------
// CONFIGURATION
// -------------------------
$AUTH_USER = 'user';
$AUTH_PASS = 'pass'; // Change this to a strong password
$UPLOAD_DIR = __DIR__ . '/files/';
//$ALLOWED_TYPES = ['image/png', 'image/jpeg', 'application/pdf', 'text/plain']; // optional
$ALLOWED_TYPES = [];

// Rate limiting configuration
$RATE_LIMIT_DIR = __DIR__ . '/rate_limits/';
$RATE_LIMIT = 1024 * 1024 * 1024; // 1024 MB per IP per 24 hours
$RATE_LIMIT_PERIOD = 86400; // 24 hours in seconds

// -------------------------
// ERROR REPORTING OFF
// -------------------------
error_reporting(0);
ini_set('display_errors', 0);

// -------------------------
// RATE LIMITING FUNCTIONS
// -------------------------
function get_client_ip() {
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
    } elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
        $ip = $_SERVER['HTTP_X_REAL_IP'];
    } else {
        $ip = $_SERVER['REMOTE_ADDR'];
    }
    return trim($ip);
}

function check_rate_limit($ip, $file_size) {
    global $RATE_LIMIT_DIR, $RATE_LIMIT, $RATE_LIMIT_PERIOD;
    
    if (!is_dir($RATE_LIMIT_DIR)) {
        mkdir($RATE_LIMIT_DIR, 0700, true);
    }
    
    $safe_ip = preg_replace('/[^a-zA-Z0-9\-_\.]/', '_', $ip);
    $rate_file = $RATE_LIMIT_DIR . $safe_ip . '.json';
    
    $current_time = time();
    $usage_data = [];
    
    if (file_exists($rate_file)) {
        $content = file_get_contents($rate_file);
        $usage_data = json_decode($content, true);
        if (!is_array($usage_data)) {
            $usage_data = [];
        }
    }
    
    $usage_data = array_filter($usage_data, function($entry) use ($current_time, $RATE_LIMIT_PERIOD) {
        return ($current_time - $entry['timestamp']) < $RATE_LIMIT_PERIOD;
    });
    
    $total_usage = array_sum(array_column($usage_data, 'size'));
    
    if ($total_usage + $file_size > $RATE_LIMIT) {
        return false;
    }
    
    $usage_data[] = [
        'timestamp' => $current_time,
        'size' => $file_size
    ];
    
    file_put_contents($rate_file, json_encode($usage_data, JSON_PRETTY_PRINT));
    
    return true;
}

function get_remaining_quota($ip) {
    global $RATE_LIMIT_DIR, $RATE_LIMIT, $RATE_LIMIT_PERIOD;
    
    $safe_ip = preg_replace('/[^a-zA-Z0-9\-_\.]/', '_', $ip);
    $rate_file = $RATE_LIMIT_DIR . $safe_ip . '.json';
    
    if (!file_exists($rate_file)) {
        return $RATE_LIMIT;
    }
    
    $content = file_get_contents($rate_file);
    $usage_data = json_decode($content, true);
    if (!is_array($usage_data)) {
        return $RATE_LIMIT;
    }
    
    $current_time = time();
    $usage_data = array_filter($usage_data, function($entry) use ($current_time, $RATE_LIMIT_PERIOD) {
        return ($current_time - $entry['timestamp']) < $RATE_LIMIT_PERIOD;
    });
    
    $total_usage = array_sum(array_column($usage_data, 'size'));
    return max(0, $RATE_LIMIT - $total_usage);
}

// -------------------------
// REMOVE DATE/TIME FROM FILENAME
// -------------------------
function remove_datetime_from_filename($filename) {
    $patterns = [
        '/\d{4}-\d{2}-\d{2}/',                    // YYYY-MM-DD
        '/\d{4}\d{2}\d{2}/',                      // YYYYMMDD
        '/\d{2}-\d{2}-\d{4}/',                    // DD-MM-YYYY or MM-DD-YYYY
        '/\d{2}\/\d{2}\/\d{4}/',                  // DD/MM/YYYY or MM/DD/YYYY
        '/\d{2}\.\d{2}\.\d{4}/',                  // DD.MM.YYYY
        '/\d{2}:\d{2}:\d{2}/',                    // HH:MM:SS
        '/\d{2}:\d{2}/',                          // HH:MM
        '/\d{2}-\d{2}-\d{2}/',                    // HH-MM-SS
        '/\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}/',  // ISO 8601 full datetime
        '/\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}/',        // ISO 8601 datetime without seconds
        '/\d{2}[\/\-\.]\d{2}[\/\-\.]\d{2}/',      // YY-MM-DD or similar
        '/\b\d{10}\b/',                           // 10-digit timestamp
        '/\b\d{13}\b/',                           // 13-digit millisecond timestamp
        '/\d{4}-\d{2}/',                          // YYYY-MM
        '/[Jj]an|[Ff]eb|[Mm]ar|[Aa]pr|[Mm]ay|[Jj]un|[Jj]ul|[Aa]ug|[Ss]ep|[Oo]ct|[Nn]ov|[Dd]ec/i', // Month names
        '/_\d{4}\d{2}\d{2}/',                     // _YYYYMMDD
        '/_\d{4}-\d{2}-\d{2}/',                   // _YYYY-MM-DD
    ];
    
    $sanitized = $filename;
    foreach ($patterns as $pattern) {
        $sanitized = preg_replace($pattern, '', $sanitized);
    }
    
    // Clean up resulting double underscores, dashes, or dots
    $sanitized = preg_replace('/[_\-\.]{2,}/', '_', $sanitized);
    // Remove leading/trailing underscores, dashes, or dots
    $sanitized = trim($sanitized, '_-.');
    
    return $sanitized;
}

// -------------------------
// REMOVE PREPOSITION WORDS FROM FILENAME
// -------------------------
function remove_preposition_words($filename) {
    // List of preposition words to remove (case-insensitive)
    $prepositions = [
        'from', 'by', 'to', 'via', 'till', 'until', 'at', 'in', 'on', 'with',
        'for', 'of', 'and', 'or', 'but', 'as', 'is', 'was', 'are', 'be',
        'been', 'being', 'have', 'has', 'had', 'do', 'does', 'did',
    ];
    
    $sanitized = $filename;
    
    // Remove whole word matches with word boundaries
    foreach ($prepositions as $word) {
        // Match word as a whole word (case-insensitive)
        $sanitized = preg_replace('/\b' . preg_quote($word, '/') . '\b/i', '', $sanitized);
    }
    
    // Clean up resulting multiple underscores and dashes (any combination)
    $sanitized = preg_replace('/[_\-]+/', '_', $sanitized);
    // Remove leading/trailing underscores, dashes, or dots
    $sanitized = trim($sanitized, '_-.');
    
    return $sanitized;
}

// -------------------------
// CORS HEADERS
// -------------------------
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Access-Control-Max-Age: 7200');
header('Access-Control-Allow-Origin: *');

// -------------------------
// DETECT REQUEST TYPE
// -------------------------
$request_method = $_SERVER['REQUEST_METHOD'];

// -------------------------
// QUOTA ENDPOINT
// -------------------------
if ($request_method === 'GET' && isset($_GET['quota'])) {
    $client_ip = get_client_ip();
    $remaining = get_remaining_quota($client_ip);
    $total = $RATE_LIMIT;
    header('Content-Type: application/json');
    echo json_encode([
        'remaining' => $remaining,
        'total'     => $total,
        'used'      => $total - $remaining,
    ]);
    exit;
}

// -------------------------
// FILE DOWNLOAD (GET/HEAD)
// -------------------------
if ($request_method === 'GET' || $request_method === 'HEAD') {
    $upload_file_name = substr($_SERVER['PHP_SELF'], strlen($_SERVER['SCRIPT_NAME'])+1);
    $sanitized_name = basename($upload_file_name);
    $store_file_name = $UPLOAD_DIR . $sanitized_name;

    if (file_exists($store_file_name)) {
        $mime_type = @file_get_contents($store_file_name . '-type');
        if ($mime_type === FALSE) {
            $mime_type = 'application/octet-stream';
            header('Content-Disposition: attachment');
        }
        
        header('Content-Type: ' . $mime_type);
        header('Content-Length: ' . filesize($store_file_name));
        header("Content-Security-Policy: default-src 'none'");
        header("X-Content-Security-Policy: default-src 'none'");
        header("X-WebKit-CSP: default-src 'none'");
        
        if ($request_method !== 'HEAD') {
            readfile($store_file_name);
        }
    } else {
        header('HTTP/1.0 404 Not Found');
    }
    exit;
}

// -------------------------
// OPTIONS (CORS preflight)
// -------------------------
if ($request_method === 'OPTIONS') {
    exit;
}

// -------------------------
// BASIC HTTP AUTH (for POST uploads/deletes)
// -------------------------
if ($request_method === 'POST') {
    if (!isset($_SERVER['PHP_AUTH_USER']) || 
        $_SERVER['PHP_AUTH_USER'] !== $AUTH_USER || 
        $_SERVER['PHP_AUTH_PW'] !== $AUTH_PASS) {
        header('WWW-Authenticate: Basic realm="Uploader"');
        header('HTTP/1.0 401 Unauthorized');
        echo 'Authentication required.';
        exit;
    }

    // -------------------------
    // EARLY QUOTA CHECK (using Content-Length, before file is buffered)
    // This rejects oversized uploads immediately for both web and CLI uploads.
    // -------------------------
    $content_length = isset($_SERVER['CONTENT_LENGTH']) ? (int)$_SERVER['CONTENT_LENGTH'] : 0;
    if ($content_length > 0) {
        $client_ip = get_client_ip();
        $remaining = get_remaining_quota($client_ip);
        if ($content_length > $remaining) {
            http_response_code(429);
            echo 'Rate limit exceeded. You have ' . round($remaining / 1024 / 1024, 2) . ' MB remaining in your 24-hour quota.';
            exit;
        }
    }

    // -------------------------
    // FILE DELETE HANDLING
    // -------------------------
    if (isset($_POST['delete'])) {
        $fileToDelete = basename($_POST['delete']); // sanitize filename
        $target = $UPLOAD_DIR . $fileToDelete;

        if (file_exists($target)) {
            if (unlink($target)) {
                @unlink($target . '-type'); // Also delete type file if exists
                echo 'Deleted successfully';
                exit;
            } else {
                http_response_code(500);
                echo 'Failed to delete file.';
                exit;
            }
        } else {
            http_response_code(404);
            echo 'File not found.';
            exit;
        }
    }

    // -------------------------
    // FILE UPLOAD HANDLING
    // -------------------------
    if (isset($_FILES['file'])) {
        $file = $_FILES['file'];

        // Check for errors
        if ($file['error'] !== UPLOAD_ERR_OK) {
            http_response_code(400);
            echo 'Upload error.';
            exit;
        }

        // Optional MIME type check
        if (!empty($ALLOWED_TYPES) && !in_array($file['type'], $ALLOWED_TYPES)) {
            http_response_code(400);
            echo 'File type not allowed.';
            exit;
        }

        // Rate limiting check
        // This records the usage after the early check already passed.
        $client_ip = get_client_ip();
        
        if (!check_rate_limit($client_ip, $file['size'])) {
            $remaining = get_remaining_quota($client_ip);
            http_response_code(429);
            echo 'Rate limit exceeded. You have ' . round($remaining / 1024 / 1024, 2) . ' MB remaining in your 24-hour quota.';
            exit;
        }

        // Check if upload directory exists (normal files)
        if (!is_dir($UPLOAD_DIR)) {
            http_response_code(500);
            echo 'Upload directory not available.';
            exit;
        }

        // -------------------------
        // Generate short random string and append to original filename
        // -------------------------
        function random_string($length = 5) {
            $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
            $str = '';
            for ($i = 0; $i < $length; $i++) {
                $str .= $chars[random_int(0, strlen($chars) - 1)];
            }
            return $str;
        }

        $originalName = basename($file['name']);
        // Sanitize original filename (remove extension first)
        $ext = pathinfo($originalName, PATHINFO_EXTENSION);
        $nameWithoutExt = pathinfo($originalName, PATHINFO_FILENAME);
        $nameWithoutExt = remove_datetime_from_filename($nameWithoutExt);
        $nameWithoutExt = remove_preposition_words($nameWithoutExt);
        $nameWithoutExt = preg_replace('/[^A-Za-z0-9_\-]/', '_', $nameWithoutExt);
        // Remove multiple consecutive underscores and dashes
        $nameWithoutExt = preg_replace('/[_\-]+/', '_', $nameWithoutExt);
        $nameWithoutExt = trim($nameWithoutExt, '_-');

        // Generate random string and append
        do {
            $random = random_string();
            $filename = $nameWithoutExt . '_' . $random . ($ext ? '.' . $ext : '');
            $target = $UPLOAD_DIR . $filename;
        } while (file_exists($target));

        // Move uploaded file
        if (!move_uploaded_file($file['tmp_name'], $target)) {
            http_response_code(500);
            echo 'Failed to save file.';
            exit;
        }

        // Store MIME type for consistency
        file_put_contents($target . '-type', $file['type']);

        // Return public URL
        $url = 'https://' . $_SERVER['HTTP_HOST'] . '/files/' . basename($target);
        echo $url;
        exit;
    }

    // -------------------------
    // DEFAULT RESPONSE
    // -------------------------
    http_response_code(405);
    echo 'Only POST with file upload is supported.';
}

// -------------------------
// INVALID REQUEST METHOD
// -------------------------
header('HTTP/1.0 400 Bad Request');
?>
