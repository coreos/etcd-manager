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
}

func deployFromEtcdBinary(path string, hosts []string) {
	copyOnAll(hosts, path)
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

func connectAndExec(host string, commands []string, wg *sync.WaitGroup) {
	defer wg.Done()
	client, err := ssh.Dial("tcp", host, clientConfig)
	if err != nil {
		log.Println("Failed to dial: ", err.Error())
		return
	}

	for _, command := range commands {
		if verbose {
			fmt.Printf("%s:\n    => executing %s\n", host, command)
		}
		session, err := client.NewSession()
		if err != nil {
			panic("Failed to create session: " + err.Error())
		}
		defer session.Close()

		var b bytes.Buffer
		session.Stdout = &b

		if err := session.Run(command); err != nil {
			log.Println("Failed to run: ", err.Error())
			return
		}
		output := b.String()
		if output != "" {
			fmt.Printf("%s:\n    => %s", host, output)
		}
	}
}

func connectAndUpload(host string, r io.Reader, wg *sync.WaitGroup) {
	defer wg.Done()
	client, err := ssh.Dial("tcp", host, clientConfig)
	if err != nil {
		log.Println("Failed to dial: ", err.Error())
		return
	}

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		log.Println("Failed to create sftp client:", err)
		return
	}

	f, err := sftpClient.Create("/tmp/etcd")
	if err != nil {
		log.Println("failed to create file")
		return
	}
	defer f.Close()

	fmt.Println("copying etcd binary to", host)
	if _, err := io.Copy(f, r); err != nil {
		log.Println("failed to copy file")
		return
	}

	if err := sftpClient.Chmod("/tmp/etcd", 0755); err != nil {
		log.Println("failed to chmod remote etcd binary")
		return
	}
}
