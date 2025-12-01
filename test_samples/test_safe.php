<?php
// Safe PHP code - should show "No Vulnerabilities" message

// Using prepared statements (SAFE)
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$user_id]);
$result = $stmt->fetchAll();

// Using mysqli prepared statements (SAFE)
$stmt = mysqli_prepare($conn, "SELECT * FROM products WHERE category = ?");
mysqli_stmt_bind_param($stmt, "s", $category);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

// Constant assignment (SAFE)
$table_name = "users";
$limit = 10;

// Safe numeric casting (SAFE)
$id = (int)$_GET['id'];
$query = "SELECT * FROM users WHERE id = $id";

echo "This is a safe PHP file!";
?>
