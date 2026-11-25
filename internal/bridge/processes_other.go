//go:build !windows

package bridge

import "context"

func listRunningProcessDetailsPlatform(ctx context.Context) ([]ProcessInfo, error) {
	names, err := ListRunningProcesses(ctx)
	if err != nil {
		return nil, err
	}
	items := make([]ProcessInfo, 0, len(names))
	for _, n := range names {
		items = append(items, ProcessInfo{Name: n})
	}
	return items, nil
}
