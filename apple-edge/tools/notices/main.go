// Command notices writes THIRD_PARTY_NOTICES.txt for the packages given on
// the command line: the license texts (and NOTICE or PATENTS files) of every
// module linked in, read from the module cache, plus Go's own license. It
// fails if a module that must never be linked is found.
//
//	go run ./tools/notices -o THIRD_PARTY_NOTICES.txt ./cmd/apple-edge
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// forbidden modules: copyleft or unmaintained storage backends of the
// upstream projects, present in the module graph but never to be linked.
var forbidden = []string{
	"github.com/go-sql-driver/mysql",
	"github.com/boltdb/bolt",
	"github.com/RobotsAndPencils/buford",
	"github.com/peterbourgon/diskv",
}

var licenseFiles = []string{"LICENSE", "LICENSE.txt", "LICENSE.md", "LICENCE", "COPYING", "NOTICE", "NOTICE.txt", "PATENTS"}

type module struct {
	Path    string
	Version string
	Dir     string
	Main    bool
	Replace *module
}

type pkg struct {
	ImportPath string
	Standard   bool
	Module     *module
}

func main() {
	out := flag.String("o", "THIRD_PARTY_NOTICES.txt", "output file")
	flag.Parse()
	pkgs := flag.Args()
	if len(pkgs) == 0 {
		pkgs = []string{"./cmd/apple-edge"}
	}
	if err := run(*out, pkgs); err != nil {
		fmt.Fprintln(os.Stderr, "notices:", err)
		os.Exit(1)
	}
}

func run(out string, pkgs []string) error {
	cmd := exec.Command("go", append([]string{"list", "-deps", "-json"}, pkgs...)...)
	cmd.Stderr = os.Stderr
	raw, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("go list: %w", err)
	}
	mods := map[string]*module{}
	std := false
	dec := json.NewDecoder(bytes.NewReader(raw))
	for {
		var p pkg
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return err
		}
		if p.Standard {
			std = true
			continue
		}
		if p.Module == nil || p.Module.Main {
			continue
		}
		m := p.Module
		if m.Replace != nil {
			m = m.Replace
		}
		for _, f := range forbidden {
			if m.Path == f || strings.HasPrefix(m.Path, f+"/") {
				return fmt.Errorf("forbidden module linked: %s (via %s)", m.Path, p.ImportPath)
			}
		}
		mods[m.Path] = m
	}
	var b strings.Builder
	b.WriteString("THIRD-PARTY SOFTWARE NOTICES\n\nThis program includes the following components, distributed under their own licenses.\n")
	if std {
		goroot, err := exec.Command("go", "env", "GOROOT").Output()
		if err != nil {
			return err
		}
		root := strings.TrimSpace(string(goroot))
		if err := appendFiles(&b, "The Go standard library", root); err != nil {
			return err
		}
	}
	paths := make([]string, 0, len(mods))
	for p := range mods {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		m := mods[p]
		if err := appendFiles(&b, m.Path+" "+m.Version, m.Dir); err != nil {
			return err
		}
	}
	return os.WriteFile(out, []byte(b.String()), 0o644)
}

func appendFiles(b *strings.Builder, title, dir string) error {
	found := false
	for _, name := range licenseFiles {
		text, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		found = true
		fmt.Fprintf(b, "\n================================================================================\n%s (%s)\n================================================================================\n\n%s\n",
			title, name, strings.TrimSpace(string(text)))
	}
	if !found {
		return fmt.Errorf("no license file for %s in %s", title, dir)
	}
	return nil
}
