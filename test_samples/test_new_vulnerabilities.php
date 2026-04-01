<?php
// Test file for new vulnerability detection patterns added to detect_lines.py.
// Every "UNSAFE" block should be flagged; every "SAFE" block should be clean.

// -----------------------------------------------------------------------
// 1. $_SERVER user-controlled keys (NEW TAINT SOURCE)
// -----------------------------------------------------------------------

// UNSAFE: HTTP_REFERER is user-controlled
$referer = $_SERVER['HTTP_REFERER'];
$query = "SELECT * FROM logs WHERE referer = '" . $referer . "'";
mysqli_query($conn, $query);

// UNSAFE: REQUEST_URI is user-controlled
$uri = $_SERVER['REQUEST_URI'];
$sql = "INSERT INTO hits (uri) VALUES ('" . $uri . "')";
mysqli_query($conn, $sql);

// -----------------------------------------------------------------------
// 2. Taint laundering fix — OR semantics (FIXED TAINT PROPAGATION)
// -----------------------------------------------------------------------

// UNSAFE: $safe is clean but $tainted is not; the concatenation result is tainted
$tainted = $_GET['input'];
$safe = "literal_prefix_";
$combined = $safe . $tainted;   // $combined must remain tainted (OR logic)
$query3 = "SELECT * FROM items WHERE name = '" . $combined . "'";
mysqli_query($conn, $query3);

// -----------------------------------------------------------------------
// 3. Command injection (CWE-78) — NEW SINK
// -----------------------------------------------------------------------

// UNSAFE: user input passed directly to exec()
$cmd_input = $_GET['cmd'];
exec($cmd_input, $output);

// UNSAFE: user input used in shell_exec with string concatenation
$filename = $_POST['filename'];
$result = shell_exec("cat " . $filename);

// UNSAFE: user input passed to system()
$tool = $_REQUEST['tool'];
system($tool);

// UNSAFE: user input passed to passthru()
$query_str = $_GET['q'];
passthru("grep " . $query_str . " /var/log/app.log");

// SAFE: no user input reaches the command sink
$fixed_cmd = "ls -la /var/www/html";
exec($fixed_cmd, $out);

// -----------------------------------------------------------------------
// 4. File inclusion (CWE-98) — NEW SINK
// -----------------------------------------------------------------------

// UNSAFE: tainted path in include
$page = $_GET['page'];
include($page . ".php");

// UNSAFE: tainted path in require_once
$module = $_POST['module'];
require_once("modules/" . $module . ".php");

// SAFE: constant string in include
include("templates/header.php");

// -----------------------------------------------------------------------
// 5. sprintf with %s should NOT sanitise tainted input (FIXED)
// -----------------------------------------------------------------------

// UNSAFE: sprintf with %s does NOT prevent SQL injection
$user_input = $_GET['search'];
$sprintf_query = sprintf("SELECT * FROM products WHERE name LIKE '%%%s%%'", $user_input);
mysqli_query($conn, $sprintf_query);

// SAFE: sprintf with %d is safe because it coerces to integer
$safe_id = $_GET['id'];
$safe_query = sprintf("SELECT * FROM users WHERE id = %d", $safe_id);
mysqli_query($conn, $safe_query);

// -----------------------------------------------------------------------
// 6. Additional SQL drivers (EXPANDED SINKS)
// -----------------------------------------------------------------------

// UNSAFE: pg_query (PostgreSQL)
$pg_input = $_GET['name'];
$pg_query = "SELECT * FROM pg_users WHERE name = '" . $pg_input . "'";
pg_query($pg_conn, $pg_query);

// UNSAFE: sqlsrv_query (Microsoft SQL Server)
$mssql_input = $_POST['id'];
$mssql_query = "SELECT * FROM mssql_table WHERE id = " . $mssql_input;
sqlsrv_query($mssql_conn, $mssql_query);

// -----------------------------------------------------------------------
// 7. intval / floatval as SQL-safe sanitisers (EXPANDED SANITISERS)
// -----------------------------------------------------------------------

// SAFE: intval() clears the taint for an integer context
$raw_id = $_GET['id'];
$safe_int_id = intval($raw_id);
$int_query = "SELECT * FROM users WHERE id = " . $safe_int_id;
mysqli_query($conn, $int_query);

// SAFE: floatval() clears the taint for a float context
$raw_price = $_GET['price'];
$safe_price = floatval($raw_price);
$price_query = "SELECT * FROM products WHERE price > " . $safe_price;
mysqli_query($conn, $price_query);

// UNSAFE: mysql_real_escape_string was previously not in sanitiser list;
// it IS a SQL sanitiser, so the result should now be safe
$raw_name = $_GET['name'];
$escaped_name = mysql_real_escape_string($raw_name);
$name_query = "SELECT * FROM users WHERE name = '" . $escaped_name . "'";
mysql_query($name_query);

echo "Test complete";
?>
