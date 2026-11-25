package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"cs-burp-router/internal/bridge"
	"cs-burp-router/internal/detector"
	"cs-burp-router/internal/forwarder"
	"cs-burp-router/internal/socks5"
	"cs-burp-router/internal/tracker"
	"cs-burp-router/internal/web"
)

func main() {
	listenAddr := flag.String("listen", socks5.DefaultListenAddr, "Local SOCKS5 listen address (host:port)")
	burpAddr := flag.String("burp", forwarder.DefaultBurpAddr, "Local Burp Suite proxy address (host:port)")
	webAddr := flag.String("web", web.DefaultListenAddr, "Local Web dashboard listen address (host:port)")
	bridgeBin := flag.String("bridge-bin", "", "Optional path to ProxyBridge_CLI.exe")
	noBrowser := flag.Bool("no-browser", false, "Do not open Web dashboard in default browser automatically")
	flag.Parse()

	logger := log.New(os.Stdout, "[cs-burp-router] ", log.LstdFlags|log.Lmicroseconds)

	if _, _, err := net.SplitHostPort(*burpAddr); err != nil {
		logger.Fatalf("invalid -burp address %q: %v", *burpAddr, err)
	}

	socksLn, err := listenLoopback(*listenAddr)
	if err != nil {
		logger.Fatalf("failed to bind SOCKS5 listener on %s: %v", *listenAddr, err)
	}
	webLn, err := listenLoopback(*webAddr)
	if err != nil {
		_ = socksLn.Close()
		logger.Fatalf("failed to bind Web UI listener on %s: %v", *webAddr, err)
	}

	actualSocksAddr := socksLn.Addr().String()
	actualWebAddr := webLn.Addr().String()

	connTracker := tracker.New(tracker.DefaultCapacity)
	det := detector.NewDefault()
	fwd := forwarder.New(forwarder.Config{
		BurpAddr: *burpAddr,
	})
	bridgeMgr := bridge.NewManager(bridge.ManagerConfig{
		BinaryPath: *bridgeBin,
		SocksAddr:  actualSocksAddr,
		Logger:     logger,
	})

	socksSrv := socks5.NewServer(socks5.Config{
		ListenAddr:  actualSocksAddr,
		Detector:    det,
		Forwarder:   fwd,
		BypassAddrs: []string{actualWebAddr},
		Logger:      logger,
		Hooks: socks5.LifecycleHooks{
			OnConnStart: func(ev socks5.ConnStartEvent) uint64 {
				return connTracker.Start(tracker.StartEntry{
					Timestamp:  ev.Time,
					ClientAddr: ev.ClientAddr,
					Target:     ev.TargetAddr,
					Protocol:   ev.Protocol,
					Action:     string(ev.Action),
				})
			},
			OnConnEnd: func(id uint64, err error) {
				connTracker.Finish(id, err)
			},
		},
		OnDecision: func(ev socks5.DecisionEvent) {
			logger.Printf(
				"ROUTE %s -> %s | proto=%s | action=%s | reason=%s",
				ev.ClientAddr,
				ev.TargetAddr,
				ev.Protocol,
				ev.Action,
				ev.Reason,
			)
		},
	})

	webSrv := web.NewServer(web.Config{
		ListenAddr:  actualWebAddr,
		Tracker:     connTracker,
		Detector:    det,
		Forwarder:   fwd,
		SocksServer: socksSrv,
		Bridge:      bridgeMgr,
		Logger:      logger,
	})

	dashboardURL := "http://" + actualWebAddr
	logger.Printf(
		"SOCKS5 listening on %s | Burp target=%s | Web UI=%s | is_admin=%v",
		actualSocksAddr,
		fwd.BurpAddr(),
		dashboardURL,
		bridge.IsProcessAdmin(),
	)

	errCh := make(chan error, 2)
	go func() {
		if err := socksSrv.Serve(socksLn); err != nil {
			errCh <- fmt.Errorf("socks5 server: %w", err)
		}
	}()
	go func() {
		if err := webSrv.Serve(webLn); err != nil {
			errCh <- fmt.Errorf("web server: %w", err)
		}
	}()

	web.LaunchDashboardConsole(webSrv.LaunchURL(), *noBrowser, logger)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		logger.Printf("received signal %v, shutting down gracefully...", sig)
	case serveErr := <-errCh:
		logger.Printf("server error: %v, shutting down...", serveErr)
	}

	// 禁止启动新实例后再停止当前 ProxyBridge 并清理临时配置。
	if err := bridgeMgr.Shutdown(); err != nil {
		logger.Printf("bridge manager stop error: %v", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := webSrv.Shutdown(shutdownCtx); err != nil {
		logger.Printf("web server shutdown error: %v", err)
	}
	if err := socksSrv.Close(); err != nil {
		logger.Printf("socks5 server close error: %v", err)
	}
	logger.Printf("shutdown complete")
}

func listenLoopback(addr string) (net.Listener, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(host, "localhost") {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("listen host must be a loopback address")
	}
	return net.Listen("tcp", net.JoinHostPort(ip.String(), port))
}
