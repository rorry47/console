<?php
if (isset($_POST['command'])) {

$arr_com = explode(' ',trim(strtolower($_POST['command'])));

$command = $arr_com[0];




//////////////////////////////////////////////////////


$version = 'Version: 1.2';


//////////////////////////////////////////////////////


//// whois
        if ($command == 'whois') {

         //   echo $arr_com[1];

        if (empty($arr_com[1])) {
        echo "whois: no ip or domain";

        } else {
            $domain = str_replace(' ', '', @$arr_com[1]);

            $error = array('NULL','no_domain');
            if (empty($domain)) {echo "no domain"; exit();}

            if ($domain == "0.0.0.0") {echo "bad_ip";exit();}
            if(!empty($domain)){
            $arrays = array("\\", "#", "'", "\"", "<", "%", "/", ">", "*", "$", "_", ":", "?", "(", ")", ";", "\@");
            $full_domain = str_replace($arrays, "", trim(mb_substr($domain, 0, 128)));

            exec("whois $full_domain", $output, $status);
            foreach($output as $myarr)
            {
              echo $myarr."<br />";
            }

            } else {
            echo 'bad domain';
            }

        }
            exit();
        }
/////////////


////passgen
        if ($command == 'passgen') {
                $arr = range(1, 20);
                foreach ($arr as $i) {
                        $bytes = openssl_random_pseudo_bytes(12);
                        $pass = bin2hex($bytes);
                        echo $pass, '<br>';
                }
                exit();
        }
////////////



//////////////LIST
if ($command == 'list') {
        if ($arr_com[1] == "proxy") {
                echo file_get_contents("https://raw.githubusercontent.com/shiftytr/proxy-list/master/proxy.txt");
                exit();
        }
        if ($arr_com[1] == "http") {
                echo file_get_contents("https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt");
                exit();
        }
        if ($arr_com[1] == "socks5") {
                echo file_get_contents("https://raw.githubusercontent.com/shiftytr/proxy-list/master/socks5.txt");
                exit();
        }
        if ($arr_com[1] == "socks4") {
                echo file_get_contents("https://raw.githubusercontent.com/shiftytr/proxy-list/master/socks4.txt");
                exit();
        } else {
        echo "list: has no arguments";
        exit();
        }


}
//////////////


//// ping
        if ($command == 'ping') {
                            if (empty($arr_com[1])) {
                            echo "ping: no ip or domain";

                            } else {
                                $ip = str_replace(' ', '', @$arr_com[1]);

                                $error = array('BAD IP','no_domain');
                                if (empty($ip)) {echo json_encode(array('error' => $error[1])); exit();}

                                if(filter_var(gethostbyname($ip), FILTER_VALIDATE_IP)){
                                $arrays = array("\\", "#", "'", "\"", "<", "%", "/", ">", "*", "$", "_", ":", "?", "(", ")", ";", "\@");

                                exec("ping -c 4 -A $ip", $output, $status);

                                foreach($output as $myarr)
                                {
                                  echo $myarr."<br />";
                                }

                                } else {
                                echo $error[0];
                                }
                                }
            exit();
        }
////////////





//// nslookup
        if ($command == 'nslookup') {
                            if (empty($arr_com[1])) {
                            echo "nslookup: no ip or domain";

                            } else {
                                $ip = str_replace(' ', '', @$arr_com[1]);

                                $error = array('BAD IP','no_domain');
                                if (empty($ip)) {echo json_encode(array('error' => $error[1])); exit();}

                                if(filter_var(gethostbyname($ip), FILTER_VALIDATE_IP)){
                                $arrays = array("\\", "#", "'", "\"", "<", "%", "/", ">", "*", "$", "_", ":", "?", "(", ")", ";", "\@");

                                exec("nslookup -type=any $ip | tail -n +4 ", $output, $status);

                                foreach($output as $myarr)
                                {
                                  echo $myarr."<br />";
                                }

                                } else {
                                echo $error[0];
                                }
                                }
            exit();
        }
////////////


//// ptr
        if ($command == 'ptr') {
                            if (empty($arr_com[1])) {
                            echo "ptr: no ip";

                            } else {
                                $ip = str_replace(' ', '', @$arr_com[1]);

                                $error = array('BAD IP','no_domain');
                                if (empty($ip)) {echo json_encode(array('error' => $error[1])); exit();}

                                if(filter_var(gethostbyname($ip), FILTER_VALIDATE_IP)){
                                $arrays = array("\\", "#", "'", "\"", "<", "%", "/", ">", "*", "$", "_", ":", "?", "(", ")", ";", "\@");

                                exec("dig -x $ip +short", $output, $status);

                                foreach($output as $myarr)
                                {
                                  echo $myarr."<br />";
                                }

                                } else {
                                echo $error[0];
                                }
                                }
            exit();
        }
////////////






//// httping
        if ($command == 'httping') {
                            if (empty($arr_com[1])) {
                            echo "httping: no ip or domain";

                            } else {
                                $ip = str_replace(' ', '', @$arr_com[1]);

                                $error = array('BAD IP','no_domain');
                                if (empty($ip)) {echo json_encode(array('error' => $error[1])); exit();}

                                if(filter_var(gethostbyname($ip), FILTER_VALIDATE_IP)){
                                $arrays = array("\\", "#", "'", "\"", "<", "%", "/", ">", "*", "$", "_", ":", "?", "(", ")", ";", "\@");

                                exec("httping -c 4 -A $ip", $output, $status);

                                foreach($output as $myarr)
                                {
                                  echo $myarr."<br />";
                                }

                                } else {
                                echo $error[0];
                                }
                                }
            exit();
        }
////////////





//// tracert
        if ($command == 'tracert') {
                            if (empty($arr_com[1])) {
                            echo "tracert: no ip or domain";

                            } else {
                                $ip = str_replace(' ', '', @$arr_com[1]);

                                $error = array('BAD IP','no_domain');
                                if (empty($ip)) {echo json_encode(array('error' => $error[1])); exit();}

                                if(filter_var(gethostbyname($ip), FILTER_VALIDATE_IP)){
                                $arrays = array("\\", "#", "'", "\"", "<", "%", "/", ">", "*", "$", "_", ":", "?", "(", ")", ";", "\@");

                                exec("traceroute $ip", $output, $status);

                                foreach($output as $myarr)
                                {
                                  echo $myarr."<br />";
                                }

                                } else {
                                echo $error[0];
                                }
                                }
            exit();
        }
////////////






//// nmap
        if ($command == 'nmap') {
                            if (empty($arr_com[1])) {
                            echo "nmap: no ip or domain";

                            } else {
                                $ip = str_replace(' ', '', @$arr_com[1]);

                                $error = array('BAD IP','no_domain');
                                if (empty($ip)) {echo json_encode(array('error' => $error[1])); exit();}
                                if ($ip == '127.0.0.1' || $ip == 'localhost') { exit(); }
                                if(filter_var(gethostbyname($ip), FILTER_VALIDATE_IP)){
                                $arrays = array("\\", "#", "'", "\"", "<", "%", "/", ">", "*", "$", "_", ":", "?", "(", ")", ";", "\@");

                                exec("nmap -F $ip | grep -v 'Nmap'", $output, $status);

                                foreach($output as $myarr)
                                {
                                  echo $myarr."<br />";
                                }

                                } else {
                                echo $error[0];
                                }
                                }
            exit();
        }
///////




//// curl
        if ($command == 'curl') {
                    if (empty($arr_com[1])) {
                    echo "curl: no ip or domain";

                    } else {
                        $domain = str_replace(' ', '', @$arr_com[1]);

                        $error = array('NULL','no_domain');
                        if (empty($domain)) {echo json_encode(array('error' => $error[1])); exit();}

                        if ($domain == "0.0.0.0") {echo "bad_ip";exit();}
                        if(!empty($domain)){
                        $arrays = array("\\", "#", "'", "\"", "<", "%", "/", ">", "*", "$", "_", ":", "?", "(", ")", ";", "\@");
                        $full_domain = str_replace($arrays, "", trim(mb_substr($domain, 0, 128)));

                        exec("curl -I $full_domain | grep ':'", $output, $status);
                        foreach($output as $myarr)
                        {
                          echo $myarr."<br />";
                        }

                        } else {
                        echo $error[0];
                        }
                        }
            exit();
        }
/////////////


//////dig
if ($command == 'dig') {
        if (empty($arr_com[1])) {
        echo "dig: no ip or domain";

        } else {
            $domain = str_replace(' ', '', @$arr_com[1]);

            $error = array('NULL','no_domain');
            if (empty($domain)) {echo json_encode(array('error' => $error[1])); exit();}

            if ($domain == "0.0.0.0") {echo "bad_ip";exit();}
            if(!empty($domain)){
            $arrays = array("\\", "#", "'", "\"", "<", "%", "/", ">", "*", "$", "_", ":", "?", "(", ")", ";", "\@");
            $full_domain = str_replace($arrays, "", trim(mb_substr($domain, 0, 128)));

            exec("dig ANY $full_domain | grep -v ';'", $output, $status);
            foreach($output as $myarr)
            {
              echo $myarr."<br />";
            }

            } else {
            echo $error[0];
            }
            }
exit();
}








//// ssl
        if ($command == 'ssl') {
        if (empty($arr_com[1])) {
        echo "ssl: no domain or ip";

        } else {
            $domain = str_replace(' ', '', @$arr_com[1]);
            $error = array('NULL','no_domain');
            if (empty($domain)) {echo json_encode(array('error' => $error[1])); exit();}

            if ($domain == "0.0.0.0") {echo "bad_ip";exit();}
            if(!empty($domain)){
            $arrays = array("\\", "#", "'", "\"", "<", "%", "/", ">", "*", "$", "_", ":", "?", "(", ")", ";", "\@");
            $full_domain = str_replace($arrays, "", trim(mb_substr($domain, 0, 128)));

            $issuer = exec("echo | openssl s_client -servername $full_domain -connect $full_domain:443 2>/dev/null | openssl x509 -noout -issuer -subject -dates | head -n1 | cut -f2-20 -d' '");
            $subject = exec("echo | openssl s_client -servername $full_domain -connect $full_domain:443 2>/dev/null | openssl x509 -noout -issuer -subject -dates | sed -n 2p | cut -f2-20 -d' '");
            $valid_from = exec("echo | openssl s_client -servername $full_domain -connect $full_domain:443 2>/dev/null | openssl x509 -noout -issuer -subject -dates | sed -n 3p | cut -f2-20 -d' '");
            $valid_by = exec("echo | openssl s_client -servername $full_domain -connect $full_domain:443 2>/dev/null | openssl x509 -noout -issuer -subject -dates | sed -n 4p | cut -f2-20 -d' '");

            $result =
            'issuer: ' . $issuer . '<br>' .
            'subject: ' . $subject . '<br>' .
            'valid_from: ' . $valid_from . '<br>' .
            'valid_by: ' . $valid_by . '<br>';
            echo $result;
            } else {
            echo $error[0];
            }
            }
            exit();
        }
//////

if ($command == 'info') {
echo $version;
echo '<br />Hello, this is the console from xyjeck.com!<br />If you have any suggestions or questions about <br />the work of the blog or this console, please contact telegram: <a href="https://t.me/rorry_4_7" target="_blank">@rorry_4_7</a><br /><br />';
echo "> Update information<br /><br />";
$uodate_info = file_get_contents('./readme');
echo $uodate_info;
exit();
}


if ($command == 'color') {
       if ($arr_com[1] == "a") {
                $_SESSION['style'] = 'A';
                header("location: /console/");
                exit();
        }
       if ($arr_com[1] == "b") {
                $_SESSION['style'] = 'B';
                header("location: /console/");
                exit();
        }
       if ($arr_com[1] == "c") {
                $_SESSION['style'] = 'C';
                header("location: /console/");
                exit();
        }
       if ($arr_com[1] == "d") {
                $_SESSION['style'] = 'D';
                header("location: /console/");
                exit();
        }
       if ($arr_com[1] == "x") {
                $_SESSION['style'] = 'X';
                header("location: /console/");
                exit();
        }
       if ($arr_com[1] == "p") {
                $_SESSION['style'] = 'P';
                header("location: /console/");
                exit();
        }

       if (empty($arr_com[1])) {
                $_SESSION['style'] = '';
                header("location: /console/");
                exit();
        }

exit();
}


/////exit
if ($command == "exit") {
header("location: /");
exit();
}
/////


//// help
if (empty($command)) {
            echo $command  . "You have not entered a command<br>";
            echo 'Enter command "help" for commands information.';
exit();}

        if ($command == 'help') {
            echo '<br>> HELP<br>';
            echo '------------------------------------------------------------------------------------<br><br>';
            echo '<b>whois [domain] [ip] </b>------------------ services for whois domain<br>';
            echo '<b>ping [domain] [ip] </b>------------------- ping domain or ip<br>';
            echo '<b>httping [domain] [ip] </b>---------------- httping domain or ip<br>';
            echo '<b>dig [domain] </b>------------------------- check dns record for domain<br>';
            echo '<b>curl [domain] [ip] </b>------------------- server response<br>';
            echo '<b>nmap [domain] [ip] </b>------------------- scan port server<br>';
            echo '<b>ssl [domain] [ip]  </b>------------------- check infossl sertificate<br>';
            echo '<b>tracert [domain] [ip]  </b>--------------- traceroute for domain or ip<br>';
            echo '<b>nslookup [domain] [ip]  </b>-------------- check DNS for domain or ip<br>';
            echo '<b>ptr [ip]  </b>---------------------------- check PTR record for ip<br>';
            echo '<b>passgen  </b>----------------------------- password generation 20 pieces<br>';
            echo '<b>list [proxy] [http] [socks4\5] </b>------- list IP-s and port or username proxy<br>';
            echo '<br>------------------------------------------------------------------------------------<br><br>';
            echo '<b>color [A][B][C][D][X][P][] </b>----------- color themes console<br>';
            echo '<b>info </b>--------------------------------- simple text about console and contact<br>';
            echo '<b>exit </b>--------------------------------- close console end redirect to website<br>';
            echo '<br>------------------------------------------------------------------------------------<br>';
            exit();
        } else {
            echo $command  . ": command not found<br>";
            echo 'Enter command "help" for commands information.';
                exit();
        }
////
}

?>
