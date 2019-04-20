<?php

/*
MC-TEAM Tarafından Geliştirilmiştir
*/
error_reporting(0);
echo """\n 
 ███▄ ▄███▓ ▄████▄        ▄▄▄█████▓▓█████ ▄▄▄       ███▄ ▄███▓
▓██▒▀█▀ ██▒▒██▀ ▀█        ▓  ██▒ ▓▒▓█   ▀▒████▄    ▓██▒▀█▀ ██▒
▓██    ▓██░▒▓█    ▄       ▒ ▓██░ ▒░▒███  ▒██  ▀█▄  ▓██    ▓██░
▒██    ▒██ ▒▓▓▄ ▄██▒      ░ ▓██▓ ░ ▒▓█  ▄░██▄▄▄▄██ ▒██    ▒██ 
▒██▒   ░██▒▒ ▓███▀ ░        ▒██▒ ░ ░▒████▒▓█   ▓██▒▒██▒   ░██▒
░ ▒░   ░  ░░ ░▒ ▒  ░        ▒ ░░   ░░ ▒░ ░▒▒   ▓▒█░░ ▒░   ░  ░
░  ░      ░  ░  ▒             ░     ░ ░  ░ ▒   ▒▒ ░░  ░      ░
░      ░   ░                ░         ░    ░   ▒   ░      ░   
       ░   ░ ░                        ░  ░     ░  ░       ░   
           ░                                               """;                  
echo "\n MD5 HASH Algoritmasıyla Şifrelenmiş Metin Veya Sayı Dizilerini Çözmek İçin Yazılmıştır\n"; 
echo "\n by MC-TEAM \n";  
function logs($reason,$ext = "txt"){
    if(!is_dir("dosyalar")):mkdir("dosyalar","0493");
    endif;
    $fp = fopen("dosyalar/".date("m-d-y").".".$ext, "a+");
    fwrite($fp, "**|md5 Cracker|".date("g:i:sA")."|".$reason."|\n");
}
if(isset($_SERVER['argv'][1])){ 
    $str = $_SERVER['argv'][1];
	echo "\n".$_SERVER['argv'][1]; 
    $charset  = "1234567890";
    $charset .= "abcdefghijklmnopqrstuvwxyz";
    $charset .= "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    $charset .= " ~!@#$%^&*()_+|`\={}[]:;'<>,./?";
    $charset_length = strlen($charset);
    function check($string,$str){ 
        echo "\n=>".md5($string)."=>". $string ;
        if ($str == md5($string)){
            echo "\n\n\nHash Verisini Girin: ".$str;
            echo "\nAsıl Hali:".$string;
			logs($string.":".md5($string),"txt");
            echo "\n" ; exit() ; 
        } 
    }
    function recurse ($width,$position,$base_str,$str){
        global $charset, $charset_length ;
        for ($i = 0 ; $i < $charset_length ; $i++) {
            if ($position < $width - 1){
               recurse($width,$position+1,$base_str.$charset[$i],$str);
            };
            check($base_str.$charset[$i],$str);
        } 
    }
	for ($i = 6 ; $i < 32 ; $i++) {
		recurse($i,0,"",$str);
	}
} else {
	echo "\n";
	echo "\n";
}
?>
