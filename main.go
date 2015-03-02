package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var defaultGitRepoUrl = "https://github.com/coreos/etcd.git"

var (
	stdoutChan chan string
	stderrChan chan string
)

var (
	etcdBinary string
	gitCommit  string
	gitRepoUrl string
	gitTag     string
	hosts      string
	sshUser    string
	verbose    bool
)

func init() {
	flag.StringVar(&etcdBinary, "etcd-binary", "", "etcd binary to deploy")
	flag.StringVar(&gitCommit, "commit", "", "git commit to deploy")
	flag.StringVar(&gitRepoUrl, "repo-url", defaultGitRepoUrl, "git repo to deploy from")
	flag.StringVar(&gitTag, "tag", "", "git tag to deploy")
	flag.StringVar(&hosts, "hosts", "", "comma separated list of etcd hosts")
	flag.StringVar(&sshUser, "user", "core", "ssh login username")
	flag.BoolVar(&verbose, "verbose", false, "enable verbose output")
}

var clientConfig *ssh.ClientConfig

func main() {
	if !(len(os.Args) > 1) {
		log.Fatal("action required.")
	}
	action := os.Args[1]
	os.Args = append(os.Args[:1], os.Args[2:]...)

	flag.Parse()

	authSocket := os.Getenv("SSH_AUTH_SOCK")
	if authSocket == "" {
		log.Fatal("SSH_AUTH_SOCK required, check that your ssh agent is running")
	}

	agentUnixSock, err := net.Dial("unix", authSocket)
	if err != nil {
		log.Fatal(err)
	}

	agent := agent.NewClient(agentUnixSock)
	signers, err := agent.Signers()
	if err != nil {
		log.Fatal(err)
	}

	clientConfig = &ssh.ClientConfig{
		User: sshUser,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signers...)},
	}

	hostsList := strings.Split(hosts, ",")
	if !(len(hostsList) > 0) {
		log.Fatal("one or more hosts required, use the -host flag")
	}

	stderrChan = make(chan string, 0)
	stdoutChan = make(chan string, 0)
	go consoleWriter()

	switch action {
	case "deploy":
		if etcdBinary != "" {
			deployFromEtcdBinary(etcdBinary, hostsList)
			os.Exit(0)
		}
		if gitCommit != "" {
			deployFromGitCommit(gitCommit, hostsList)
			os.Exit(0)
		}
		if gitTag != "" {
			deployFromGitTag(gitTag, hostsList)
			os.Exit(0)
		}
	case "version":
		etcdVersion(hostsList)
	}
}

func consoleWriter() {
	for {
		select {
		case msg := <-stderrChan:
			fmt.Fprintf(os.Stderr, msg)
		case msg := <-stdoutChan:
			fmt.Fprintf(os.Stdout, msg)
		}
	}
}

func deployFromEtcdBinary(path string, hosts []string) {
	copyOnAll(hosts, path)
	etcdVersion(hosts)
}

func deployFromGitCommit(commit string, hosts []string) {
	commands := []string{
		"sudo bash -c 'if [ ! -e /opt/etcd ] ; then git clone https://github.com/coreos/etcd.git /opt/etcd ; fi'",
		"sudo bash -c 'cd /opt/etcd && git fetch'",
		fmt.Sprintf("sudo bash -c 'cd /opt/etcd && git reset --hard %s'", commit),
		"docker run -v /opt/etcd:/opt/etcd -t google/golang /bin/bash -c 'cd /opt/etcd && ./build'",
		"/opt/etcd/bin/etcd --version",
	}
	runOnAll(hosts, commands)
}

func deployFromGitTag(tag string, hosts []string) {
	commands := []string{
		"sudo bash -c 'if [ ! -e /opt/etcd ] ; then git clone https://github.com/coreos/etcd.git /opt/etcd ; fi'",
		"sudo bash -c 'cd /opt/etcd && git fetch'",
		"sudo bash -c 'cd /opt/etcd && git reset --hard HEAD'",
		fmt.Sprintf("sudo bash -c 'cd /opt/etcd && git checkout tags/%s'", tag),
		"docker run -v /opt/etcd:/opt/etcd -t google/golang /bin/bash -c 'cd /opt/etcd && ./build'",
		"/opt/etcd/bin/etcd --version",
	}
	runOnAll(hosts, commands)
}

func etcdVersion(hosts []string) {
	commands := []string{
		"/opt/etcd/bin/etcd --version",
	}
	runOnAll(hosts, commands)
}

func restartCluster(hosts []string) {
	commands := []string{
		"sudo bash -c 'systemctl restart etcd'",
		"sudo bash -c 'systemctl status etcd'",
	}
	for _, host := range hosts {
		connectAndExec(host, commands, nil)
	}
}

func runOnAll(hosts, commands []string) {
	var wg sync.WaitGroup
	for _, host := range hosts {
		h := host
		wg.Add(1)
		go connectAndExec(h, commands, &wg)
	}
	wg.Wait()
}

func copyOnAll(hosts []string, path string) {
	var wg sync.WaitGroup
	for _, host := range hosts {
		h := host
		wg.Add(1)
		f, err := os.Open(path)
		if err != nil {
			fmt.Println(err)
			continue
		}
		go connectAndUpload(h, f, &wg)
	}
	wg.Wait()
}

func logStderr(host, message string) {
	stderrChan <- fmt.Sprintf("%s:\n  => %s\n", host, message)
	return
}

func connectAndExec(host string, commands []string, wg *sync.WaitGroup) error {
	if wg != nil {
		defer wg.Done()
	}

	client, err := ssh.Dial("tcp", host, clientConfig)
	if err != nil {
		logStderr(host, fmt.Sprintf("failed to create SSH connection: %s\n", err))
		return err
	}

	for _, command := range commands {
		if verbose {
			logStderr(host, fmt.Sprintf("executing %s", command))
		}

		session, err := client.NewSession()
		if err != nil {
			logStderr(host, fmt.Sprintf("failed to create SSH session: %s", err))
			return err
		}

		defer session.Close()

		var b bytes.Buffer
		session.Stdout = &b

		if err := session.Run(command); err != nil {
			logStderr(host, fmt.Sprintf("error running command: %s", err))
			return err
		}

		output := b.String()
		if output != "" {
			logStderr(host, output)
		}
	}
	return nil
}

func connectAndUpload(host string, r io.Reader, wg *sync.WaitGroup) error {
	defer wg.Done()
	client, err := ssh.Dial("tcp", host, clientConfig)
	if err != nil {
		logStderr(host, fmt.Sprintf("failed to create SSH connection: %s", err))
		return err
	}

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		logStderr(host, fmt.Sprintf("failed to create sftp client: %s", err))
		return err
	}

	f, err := sftpClient.Create("/tmp/etcd")
	if err != nil {
		logStderr(host, fmt.Sprintf("failed to create /tmp/etcd: %s", err))
		return err
	}

	logStderr(host, "uploading etcd binary")

	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		logStderr(host, fmt.Sprintf("upload failed: %s", err))
		return err
	}
	f.Close()

	err = connectAndExec(host, []string{"sudo mv /tmp/etcd /opt/etcd/bin/etcd"}, nil)
	if err != nil {
		return err
	}

	if err := sftpClient.Chmod("/opt/etcd/bin/etcd", 0755); err != nil {
		logStderr(host, fmt.Sprintf("failed to chmod remote etcd binary: %s", err))
		return err
	}
	logStderr(host, "upload complete.")

	return nil
}
