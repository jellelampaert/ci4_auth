<!DOCTYPE html>
<!--[if lt IE 7]>      <html class="no-js lt-ie9 lt-ie8 lt-ie7"> <![endif]-->
<!--[if IE 7]>         <html class="no-js lt-ie9 lt-ie8"> <![endif]-->
<!--[if IE 8]>         <html class="no-js lt-ie9"> <![endif]-->
<!--[if gt IE 8]><!--> <html class="no-js"> <!--<![endif]-->
<head>
    <meta charSet="utf-8"/>
    <meta http-equiv="x-ua-compatible" content="ie=edge"/>
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no"/>
    <title>Authentication library for CodeIgniter 4</title>
    <meta name="description" content="Example Authentication for CodeIgniter 4" />
    <style type="text/css">
        body {
            display: block;
            margin: auto;
            width: 800px;
        }
        form {
            border: 1px solid #000;
            border-radius: 20px;
            display: inline-block;
            padding: 20px;
        }
        label {
            display: inline-block;
            width: 200px;
        }
    </style>
</head>
<body class="<?= $class ?? '' ?>">
    <div id="top">
        <div class="wrapper">
            <h1>CI4_Auth</h1>
        </div>
    </div>

    <div id="content">
<?php
    
    if (isset($_SESSION['success'])) {
        echo '<div class="success">';

        if (is_array($_SESSION['success'])) {
            foreach ($_SESSION['success'] as $success) {
                echo '<p>' . $success . '</p>';
            }
        } else {
            echo $_SESSION['success'];
        }

        echo '</div>';
    }
    if (isset($_SESSION['error'])) {
        echo '<div class="error">';

        if (is_array($_SESSION['error'])) {
            foreach ($_SESSION['error'] as $error) {
                echo '<p>' . $error . '</p>';
            }
        } else {
            echo $_SESSION['error'];
        }

        echo '</div>';
    }

    echo $this->renderSection('content');
?>
    </div>
    <div id="footer">
        
    </div>
    </body>
</html>