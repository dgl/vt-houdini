package main

// SPDX-License-Identifier: AGPL-3.0-or-later

import (
	"fmt"
	"runtime/debug"
	"strings"
)

func main() {
	sshServer()
}

func versionString() string {
	// You need to use go >= 1.19 or so for this to work properly.
	// It also does not work if you use "go run", but a build will work.
	commit := ""
	modified := false
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				commit = setting.Value
			}
			if setting.Key == "vcs.modified" {
				modified = setting.Value == "true"
			}
		}
	}

	// This is a condition of the AGPL license, if you run a modified version you
	// must make the changes available. The simple way to do that is fork the
	// repo below on GitHub, push your changes to it and update the repo URL.
	const repo = "https://github.com/dgl/term-sec-test"

	buf := &strings.Builder{}
	fmt.Fprintf(buf, "UNRELEASED \x1b[9m") // XXX: unreleased
	fmt.Fprintf(buf, "term-sec-test is AGPL licensed.\n")
	if commit != "" {
		commitURL := fmt.Sprintf("%v/commit/%v", repo, commit)
		prettyURL := fmt.Sprintf("%v/commit/%v", repo, commit[:7])
		fmt.Fprintf(buf, "    This version is \x1B]8;;%v\x1b\\%v\x1b]8;;\x1b\\\n", commitURL, prettyURL)
	}
	if modified {
		fmt.Fprintf(buf, "    \x1b[31mThis version is modified!\x1b[0m\n    To comply with the license please build from a pushed git commit and alter\n    the URL in the source (main.go) if needed.\n\n")
	}
	fmt.Fprintf(buf, "\x1b[0m") // XXX: unreleased
	return buf.String()
}
