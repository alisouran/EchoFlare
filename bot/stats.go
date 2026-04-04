package main

// stats.go — server resource metrics (CPU, RAM) and network packet loss.

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var lossRe = regexp.MustCompile(`(\d+)%\s+packet loss`)

type cpuStat struct{ idle, total uint64 }

func readCPUStat() (cpuStat, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuStat{}, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			break
		}
		var vals [10]uint64
		for i := 1; i < len(fields) && i <= 10; i++ {
			v, _ := strconv.ParseUint(fields[i], 10, 64)
			vals[i-1] = v
		}
		idle := vals[3] + vals[4]
		total := uint64(0)
		for _, v := range vals {
			total += v
		}
		return cpuStat{idle: idle, total: total}, nil
	}
	return cpuStat{}, fmt.Errorf("/proc/stat: cpu line not found")
}

func serverStats() string {
	s1, err1 := readCPUStat()
	time.Sleep(500 * time.Millisecond)
	s2, err2 := readCPUStat()

	cpuStr := "N/A"
	if err1 == nil && err2 == nil {
		deltaIdle := s2.idle - s1.idle
		deltaTotal := s2.total - s1.total
		if deltaTotal > 0 {
			cpuPct := 100.0 * float64(deltaTotal-deltaIdle) / float64(deltaTotal)
			cpuStr = fmt.Sprintf("%.1f%%", cpuPct)
		}
	}

	ramStr := "N/A"
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		var memTotal, memAvail uint64
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			val, _ := strconv.ParseUint(fields[1], 10, 64)
			switch fields[0] {
			case "MemTotal:":
				memTotal = val
			case "MemAvailable:":
				memAvail = val
			}
		}
		if memTotal > 0 {
			used := memTotal - memAvail
			ramStr = fmt.Sprintf("%.1f GB / %.1f GB",
				float64(used)/1024/1024,
				float64(memTotal)/1024/1024,
			)
		}
	}

	return fmt.Sprintf("CPU: %s   RAM: %s", cpuStr, ramStr)
}

func packetLoss(target string) (int, error) {
	out, err := exec.Command("ping", "-c", "10", "-W", "1", target).CombinedOutput()
	matches := lossRe.FindSubmatch(out)
	if len(matches) < 2 {
		if err != nil {
			return 0, fmt.Errorf("ping %s: %w — %s", target, err, strings.TrimSpace(string(out)))
		}
		return 0, fmt.Errorf("ping %s: could not parse output", target)
	}
	pct, _ := strconv.Atoi(string(matches[1]))
	return pct, nil
}
