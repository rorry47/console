<?php
session_start();

$g_sitekey = ''; //GOOGLE PUBLIC KEY
$secret = ''; //GOOGLE SECRET KEY
?>
<!doctype html>
<html>
<head>
<title>xyjeck@<?php echo $_SERVER['REMOTE_ADDR']; ?> - console</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<style type="text/css">
    * {
        margin: 0;
        padding: 0;
    }

    body {
        padding: 10px;
        background: #FFFFFF;
        color: #333333;
        font-family: 'Lucida Console', Monaco, monospace;
        font-size: 16px;
    }

    form {
        display: table;
        width: 100%;
        white-space: nowrap;
    }

    form div {
        display: table-cell;
        width: auto;
        padding-right: 11px;
    }

    form #command {
        width: 100%;
    }

    input {
        border: none;
        outline: none;
        background: transparent;
        width: 100%;
    }

    input:focus {
        outline: none;
    }

    pre, form, input {
        color: inherit;
        font-family: inherit;
        font-size: inherit;
    }

    pre {
        white-space: pre;
        padding-top: 10px;
    }

    code {
        color: blue;
        font-family: inherit;
        font-size: inherit;
    }

    strong {
        font-weight: bolder;
        font-family: Tahoma, Geneva, sans-serif
    }

    .error {
        color: red;
    }

    .autocomplete .guess {
        color: #a9a9a9;
    }

    .diff-header {
        color: #333;
        font-weight: bold;
    }

    .diff-sub-header {
        color: #33a;
    }

    .diff-added {
        color: #3a3;
    }

    .diff-deleted {
        color: #a33;
    }

.check {
display: block;
    width: 0px;
}

.btn {
cursor: default;
    background-color: rgb(243 244 246);
    color: rgb(0 0 0);
    border-radius: 5px;
    border: none;
    padding: 5px 20px 5px 20px;
    font-size: 17px;
    font-weight: 600;
}
</style>

<?php if (empty($_SESSION['style'])) {
echo '<style type="text/css">

        body {
            color: #CCCCCC;
            background-color: #1d1d1d;
            font-family: Terminal, monospace;
        }

        code {
            color: #6CF7FC;
        }

        .diff-header {
            color: aqua;
        }

        .diff-sub-header {
            color: #1f7184;
        }
</style>';
} ?>

<?php if ($_SESSION['style'] == 'A') {
echo '
    <style type="text/css">
        body {
            background-color: #000000;
            color: #00C000;
            font-family: monospace;
        }

        code {
            color: #00C000;
        }

        .diff-added {
            color: #23be8c;
        }
    </style>';
} ?>

<?php if ($_SESSION['style'] == 'B') {
echo '
    <style type="text/css">
        body {
            color: #000000;
            background-color: #ffffff;
            font-family: monospace;
        }

        code {
            color: #1d1d1d;
        }

        .diff-header {
            color: blue;
        }
    </style>';
} ?>


<?php if ($_SESSION['style'] == 'C') {
echo '<style type="text/css">
        body {
            color: #B8B8B8;
            background-color: #424242;
            font-family: Monaco, Courier, monospace;
        }

        code {
            color: #FFFFFF;
        }

        form, input {
            color: #FFFFFF;
        }

        .diff-header {
            color: #B8B8B8;
        }

        .diff-sub-header {
            color: #cbcbcb;
        }
    </style>';
} ?>


<?php if ($_SESSION['style'] == 'X') {
echo '    <style type="text/css">
        body {
            font-family: Monaco, Courier, monospace;
            color: #FFFFFF;
            background: #1a2a6c;
            background: -webkit-linear-gradient(to right, #1a2a6c, #b21f1f, #fdbb2d);
            background: linear-gradient(to right, #1a2a6c, #b21f1f, #fdbb2d);
        }

        code {
            color: #898989;
        }

        .diff-header {
            color: #FFF;
        }
    </style>';
} ?>

<?php if ($_SESSION['style'] == 'D') {
echo '    <style type="text/css">
        body {
            color: #FFFFFF;
            background-color: #281022;
        }

        code {
            color: #898989;
        }

        .diff-header {
            color: #FFF;
        }
    </style>';
} ?>


<?php if ($_SESSION['style'] == 'P') {
echo '    <style type="text/css">
        body {
            font-family: Monaco, Courier, monospace;
            color: #FFFFFF;
            background: #1a2a6c;
        }

        code {
            color: #898989;
        }

        .diff-header {
            color: red;
        }
    </style>';
} ?>




<script src='https://www.google.com/recaptcha/api.js' async defer ></script>

</head>

<body>

<?php
if ($_SESSION['var'] != 1) {
echo '<form class="check" method="post">
<div class="g-recaptcha" data-theme="dark" data-sitekey="' . $g_sitekey . '"></div><br />
<button type="submit" class="btn" name="ok">OK</button>
</form><br>';

if (isset($_POST['ok'])) {

  if(!isset($_POST['g-recaptcha-response']) || empty($_POST['g-recaptcha-response'])) {
        echo 'reCAPTHCA verification failed, please try again.';
    } else {
        

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, 'https://www.google.com/recaptcha/api/siteverify?secret='.$secret.'&response='.$_POST['g-recaptcha-response']);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($ch);
        curl_close($ch);
        $response = json_decode($response);

        if($response->success) {
            $_SESSION['var'] = "1";
                header("location: /console/");
                exit();
        }
         else {
            echo 'reCAPTHCA verification failed, please try again.';
                exit();
        }
    }
}
exit();
}
?>

<form method="POST">
    <div id="currentDirName">console@<span class="diff-header"><?php echo $_SERVER['REMOTE_ADDR']; ?></span> #: </div>
    <div id="command"> <input type="text" name="command" value="" autofocus></div>
</form>
<pre><code>
<?php
require('./console.php');
?>
</code></pre>
</body>
</html>
