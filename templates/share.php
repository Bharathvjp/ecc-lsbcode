<?php
//Sharing buttons powered by https://sharingbuttons.io/
include("sharingbuttons.php");
?>

<!DOCTYPE html>
<html>
    <head>
		<link rel="stylesheet" type="text/css" href="sharingbuttons.css"/>
	</head>
	<body>
		<h1>Final year project</h1>
		<p>Share the key with image</p>
		<?php
		error_reporting (E_ALL ^ E_NOTICE);

		showSharer($_POST["run"], "A search engine site!");
		?>
		
	</body>
</html>