<?php
include("_database.php");

class Firewall {
    private $database;
    private const BLOCKLIST = "blocked_ips.txt";
    private const BLOCK_AFTER_ATTEMPTS = 3;
    private const MALICIOUS_FILES = ["repeater.php", "admin.php", "inc.php", "lv.php", "seo.php", "x.php", "b0x.php", "about.php", "cloud.php", "wso.php", "cong.php", "network.php", "css.php", "wp-2019.php", "atomlib.php", "css.php", "simple.php", "log.php", "index.php", "mail.php", "lufix.php", "doc.php", "bak.php", "content.php", "upfile.php", "wp.php", "wp-conflg.php", "bypass.php", "wp-22.php", "wp-activate.php", "404.php", "updates.php", "radio.php", "plugins.php", "xmrlpc.php", "ae.php", "moon.php", "blog.php", "themes.php", "ini.php", "as.php", "shell.php", "ws.php", "dropdown.php", "makeasmtp.php", "wp-sigunq.php", "wso112233.php", "alfanew.php", "fw.php", "install.php", "wp-login.php", "mini.php", "configs.php", "test.php", "classsmtps.php", "wp-hudbud.php", "inputs.php", "autoload_classmap.php", "text.php"];

    function __construct() {
        $this->database = new Database();
        $this->database->Connect();
    }

    function blockIP($ip) {
        $blacklist_content = file_get_contents(SELF::BLOCKLIST);

        if(str_contains($blacklist_content, $ip)){
            return;
        }
        
        file_put_contents($this->blocklist, $ip . "  deny\r\n", FILE_APPEND | LOCK_EX); 
    }

    function logInvalidAccess() {
        $request_url = $_SERVER['REDIRECT_URL'] ?? $_SERVER['REQUEST_URI'];
        $basename_request_url = basename($request_url);
        $ip = $_SERVER['REMOTE_ADDR'];

        if(in_array($basename_request_url, self::MALICIOUS_FILES)) {
            $this->blockIP($ip);
            die("You're absolutely out!");
        }

        $entries = $this->database->Query("SELECT * FROM accesslog WHERE ip = ? AND code = 404 AND created_at >= NOW() - INTERVAL 5 MINUTE", [$ip]);

        if(count($entries) > SELF::BLOCK_AFTER_ATTEMPTS) {
            $this->blockIP($ip);
        }
        
        $this->database->Execute("INSERT INTO accesslog (ip, code) VALUES (?, ?)", [$ip, 404]);
    }

}
?>
