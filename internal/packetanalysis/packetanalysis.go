package packetanalysis

import (
	"bytes"
	"os/exec"
)

type CaptureConfig struct {
	Interface  string
	Filter     string
	OutputFile string
	PacketCount int
	Duration   int
	SnapLen    int
	Promiscuous bool
}

type CapturedPacket struct {
	Number    int
	Timestamp string
	Size      int
	SrcIP     string
	DstIP     string
	SrcPort   int
	DstPort   int
	Protocol  string
	Info      string
	Data      []byte
}

type TrafficSummary struct {
	TotalPackets int
	TotalBytes   int64
	Duration     string
	Protocols    map[string]int
	TopTalkers   []Flow
	ARPCount     int
	DNSQueries   int
	HTTPReqs     int
	TLSConns     int
}

type Flow struct {
	SrcIP     string
	DstIP     string
	SrcPort   int
	DstPort   int
	Protocol  string
	Packets   int
	Bytes     int64
	StartTime string
	EndTime   string
}

type PacketAnalysisEngine struct{}

func NewPacketAnalysisEngine() *PacketAnalysisEngine {
	return &PacketAnalysisEngine{}
}

func runCapture(args ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("tshark", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return stderr.String(), err
	}
	return stdout.String(), nil
}

func runMergecap(args ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("mergecap", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return stderr.String(), err
	}
	return stdout.String(), nil
}

func runEditcap(args ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("editcap", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return stderr.String(), err
	}
	return stdout.String(), nil
}

func runTcpreplay(args ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("tcpreplay", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return stderr.String(), err
	}
	return stdout.String(), nil
}

func runCapinfos(args ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("capinfos", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return stderr.String(), err
	}
	return stdout.String(), nil
}
