<?php
session_name('developer_session');
session_start();
require_once 'developer_db.php';

if (isset($_SESSION['developer_id'])) {
    header('Location: developer_dashboard.php');
    exit();
}

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    if ($username === '' || $password === '') {
        $error = 'Please enter username and password';
    } else {
        $stmt = $dev_conn->prepare('SELECT id, username, password FROM developers WHERE username = ?');
        $stmt->bind_param('s', $username);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result && $result->num_rows === 1) {
            $dev = $result->fetch_assoc();
            if (password_verify($password, $dev['password'])) {
                $_SESSION['developer_id'] = $dev['id'];
                $_SESSION['developer_username'] = $dev['username'];
                $_SESSION['developer_name'] = $dev['username'];
                header('Location: developer_dashboard.php');
                exit();
            } else {
                $error = 'Password is incorrect';
            }
        } else {
            $error = 'Username not found';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Developer Login</title> 
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.rtl.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body { background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .login-container { background: #fff; border-radius: 18px; box-shadow: 0 8px 32px rgba(0,0,0,0.15); padding: 2.5rem 2rem; max-width: 400px; width: 100%; }
        .login-header { text-align: center; margin-bottom: 2rem; }
        .login-header i { font-size: 3rem; color: #6a11cb; margin-bottom: 1rem; }
        .form-control, .btn { font-size: 1.1rem; border-radius: 10px; }
        .btn-primary { background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%); border: none; }
        .btn-primary:hover { background: linear-gradient(135deg, #2575fc 0%, #6a11cb 100%); }
        .alert { border-radius: 10px; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <i class="fa-solid fa-code"></i>
            <h3 class="mb-0">Developer Login</h3>
        </div>
        <?php if ($error): ?>
            <div class="alert alert-danger text-center"> <?= htmlspecialchars($error) ?> </div>
        <?php endif; ?>
        <form method="POST" autocomplete="off" novalidate>
            <div class="mb-3">
                <label for="username" class="form-label">Username</label>
                <input type="text" class="form-control" id="username" name="username" required autofocus>
            </div>
            <div class="mb-4">
                <label for="password" class="form-label">Password</label>
                <input type="password" class="form-control" id="password" name="password" required>
            </div>
            <button type="submit" class="btn btn-primary w-100 mb-2">
                <i class="fa-solid fa-right-to-bracket ms-2"></i>Login
            </button>
        </form>
    </div>
</body>
</html> 