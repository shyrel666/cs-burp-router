package web

import (
	"strings"
	"testing"
)

func TestDashboardConsoleOnlyPrintsLinkOnRequest(t *testing.T) {
	var actions []string
	readDashboardCommands(strings.NewReader("\nshow link\n LINK \n\n"),
		func() { actions = append(actions, "reopen") },
		func() { actions = append(actions, "print") },
	)
	if got := strings.Join(actions, ", "); got != "reopen, print, reopen" {
		t.Fatalf("console actions = %s", got)
	}
}
