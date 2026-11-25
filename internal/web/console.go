package web

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
)

// LaunchDashboardConsole manages browser launches and local session recovery.
func LaunchDashboardConsole(url string, noBrowser bool, logger *log.Logger) {
	printLink := func() {
		fmt.Printf("Open this Web dashboard URL in your browser: %s\n", url)
	}
	interactive := isConsole(os.Stdin) && isConsole(os.Stdout)
	var opening atomic.Bool
	reopen := func() {
		if !opening.CompareAndSwap(false, true) {
			return
		}
		go func() {
			defer opening.Store(false)
			if err := openDefaultBrowser(url); err != nil {
				if interactive {
					logger.Printf("Browser launch failed: %v. Type link and press Enter to open the dashboard manually.", err)
				} else {
					logger.Printf("Browser launch failed: %v. Use -no-browser to print the dashboard link at startup.", err)
				}
			}
		}()
	}
	if noBrowser {
		printLink()
	} else {
		reopen()
	}
	if interactive {
		fmt.Println("Press Enter to reopen the Web dashboard, or type link and press Enter to display its access URL.")
		go readDashboardCommands(os.Stdin, reopen, printLink)
	}
}

func isConsole(file *os.File) bool {
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func readDashboardCommands(input io.Reader, reopen, printLink func()) {
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		switch strings.ToLower(strings.TrimSpace(scanner.Text())) {
		case "":
			reopen()
		case "link":
			printLink()
		}
	}
}

func openDefaultBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Run()
	case "darwin":
		return exec.Command("open", url).Run()
	default:
		return exec.Command("xdg-open", url).Run()
	}
}
