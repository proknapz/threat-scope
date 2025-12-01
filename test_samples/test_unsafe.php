<?php
// Unsafe PHP code - should show vulnerabilities and fixes

// UNSAFE: Direct concatenation with user input
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = '" . $id . "'";
$result = mysql_query($query);

// UNSAFE: Variable interpolation in query
$username = $_POST['username'];
$sql = "SELECT * FROM users WHERE username = '$username'";

// UNSAFE: No input validation
$category = $_GET['category'];
$query = "SELECT * FROM products WHERE category = " . $category;

// UNSAFE: Deprecated mysql_query
$search = $_REQUEST['search'];
$query = "SELECT * FROM items WHERE name LIKE '%" . $search . "%'";
mysql_query($query);

echo "This file has SQL injection vulnerabilities!";
?>
