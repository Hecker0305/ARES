package pwcracking

import (
	"bytes"
	"os/exec"
)

type CrackingEngine struct{}

type HydraResult struct {
	Target   string
	Service  string
	Port     int
	Login    string
	Password string
	Attempts int
	Status   string
}

type JohnResult struct {
	HashFile         string
	CrackedPasswords map[string]string
	Format           string
	Total            int
	Cracked          int
	Time             string
}

type HashcatResult struct {
	HashFile         string
	CrackedPasswords map[string]string
	Mode             string
	Device           string
	Speed            string
	Time             string
}

type HashFormat int

const (
	HashMD5          HashFormat = iota
	HashSHA1         HashFormat = iota
	HashSHA256       HashFormat = iota
	HashNTLM         HashFormat = iota
	HashLM           HashFormat = iota
	HashNetNTLMv1    HashFormat = iota
	HashNetNTLMv2    HashFormat = iota
	HashKerberosASREP HashFormat = iota
	HashKerberosTGS  HashFormat = iota
	HashBCrypt       HashFormat = iota
	HashSHA512Crypt  HashFormat = iota
	HashMD5Crypt     HashFormat = iota
	HashMySQL        HashFormat = iota
	HashPostgreSQL   HashFormat = iota
	HashMSSQL        HashFormat = iota
	HashOracle       HashFormat = iota
)

func NewCrackingEngine() *CrackingEngine {
	return &CrackingEngine{}
}

func runCommand(name string, args ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return stderr.String(), err
	}
	return stdout.String(), nil
}
