package pwcracking

import (
	"fmt"
	"strings"
)

func HydraBruteForce(target, service, user, passwordList string) (string, error) {
	return runCommand("hydra", "-l", user, "-P", passwordList, target, service)
}

func HydraBruteForceUserList(target, service, userList, passwordList string) (string, error) {
	return runCommand("hydra", "-L", userList, "-P", passwordList, target, service)
}

func HydraBruteForceHTTPPost(target, formData, failString string) (string, error) {
	return runCommand("hydra", "-l", "admin", "-P", "passwords.txt", target, "http-post-form", fmt.Sprintf("/:%s:%s", formData, failString))
}

func HydraBruteForceHTTPS(target, formData, failString string) (string, error) {
	return runCommand("hydra", "-l", "admin", "-P", "passwords.txt", target, "https-post-form", fmt.Sprintf("/:%s:%s", formData, failString))
}

func HydraBruteForceSSH(target, user, passwordList string) (string, error) {
	return runCommand("hydra", "-l", user, "-P", passwordList, target, "ssh")
}

func HydraBruteForceRDP(target, user, passwordList string) (string, error) {
	return runCommand("hydra", "-l", user, "-P", passwordList, target, "rdp")
}

func HydraBruteForceSMB(target, user, passwordList string) (string, error) {
	return runCommand("hydra", "-l", user, "-P", passwordList, target, "smb")
}

func HydraBruteForceFTP(target, user, passwordList string) (string, error) {
	return runCommand("hydra", "-l", user, "-P", passwordList, target, "ftp")
}

func HydraBruteForceMySQL(target, user, passwordList string) (string, error) {
	return runCommand("hydra", "-l", user, "-P", passwordList, target, "mysql")
}

func HydraBruteForceMSSQL(target, user, passwordList string) (string, error) {
	return runCommand("hydra", "-l", user, "-P", passwordList, target, "mssql")
}

func HydraBruteForceLDAP(target, user, passwordList string) (string, error) {
	return runCommand("hydra", "-l", user, "-P", passwordList, target, "ldap2")
}

func HydraBruteForcePostgreSQL(target, user, passwordList string) (string, error) {
	return runCommand("hydra", "-l", user, "-P", passwordList, target, "postgres")
}

func HydraBruteForceRedis(target, passwordList string) (string, error) {
	return runCommand("hydra", "-P", passwordList, target, "redis")
}

func HydraBruteForceSNMP(target, passwordList string) (string, error) {
	return runCommand("hydra", "-P", passwordList, target, "snmp")
}

func HydraBruteForcePOP3(target, user, passwordList string) (string, error) {
	return runCommand("hydra", "-l", user, "-P", passwordList, target, "pop3")
}

func HydraBruteForceIMAP(target, user, passwordList string) (string, error) {
	return runCommand("hydra", "-l", user, "-P", passwordList, target, "imap")
}

func HydraBruteForceVNC(target, passwordList string) (string, error) {
	return runCommand("hydra", "-P", passwordList, target, "vnc")
}

func HydraBruteForceTelnet(target, user, passwordList string) (string, error) {
	return runCommand("hydra", "-l", user, "-P", passwordList, target, "telnet")
}

func HydraBruteForceSMTP(target, user, passwordList string) (string, error) {
	return runCommand("hydra", "-l", user, "-P", passwordList, target, "smtp")
}

func HydraParseResults(output string) ([]HydraResult, error) {
	var results []HydraResult
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "login:") || strings.Contains(line, "password:") {
			parts := strings.Split(line, " ")
			r := HydraResult{Status: "parsed"}
			for i, p := range parts {
				if strings.HasPrefix(p, "login:") && i+1 < len(parts) {
					r.Login = parts[i+1]
				}
				if strings.HasPrefix(p, "password:") && i+1 < len(parts) {
					r.Password = parts[i+1]
				}
			}
			results = append(results, r)
		}
	}
	return results, nil
}

func HydraGenerateWordlist(baseWords []string, rules []string) (string, error) {
	args := []string{"-l"}
	for _, w := range baseWords {
		args = append(args, "-w", w)
	}
	for _, r := range rules {
		args = append(args, "-r", r)
	}
	out, err := runCommand("john", args...)
	return out, err
}
