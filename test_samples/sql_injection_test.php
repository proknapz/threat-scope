<?php
// Test file for SQL injection detection
// This file contains various SQL injection vulnerabilities

// 1. Direct SQL injection via GET parameter
$user_id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $user_id;
$result = mysql_query($query);

// 2. SQL injection via POST with concatenation
$username = $_POST['username'];
$password = $_POST['password'];
$sql = "SELECT * FROM users WHERE username = '" . $username . "' AND password = '" . $password . "'";

// 3. Unsafe variable interpolation
$table = $_GET['table'];
$query = "SELECT * FROM $table WHERE active = 1";

// 4. Multiple injection points
$search = $_REQUEST['search'];
$category = $_GET['category'];
$unsafe_query = "SELECT * FROM products WHERE name LIKE '%" . $search . "%' AND category = " . $category;

// 5. Safe examples (should not be flagged)
$safe_id = filter_var($_GET['id'], FILTER_VALIDATE_INT);
if ($safe_id) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$safe_id]);
}

// 6. Escaped but still potentially unsafe
$escaped_input = mysql_real_escape_string($_POST['input']);
$query = "SELECT * FROM data WHERE field = '" . $escaped_input . "'";
?>
