package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jlk/lanternis/internal/discovery"
	"github.com/jlk/lanternis/internal/httpserver"
	"github.com/jlk/lanternis/internal/store"
)

// Set at link time, e.g. go build -ldflags "-X main.version=1.2.3"
var version = "dev"

func main() {
	var (
		addr   = flag.String("addr", "127.0.0.1:8080", "HTTP listen address (loopback only)")
		dbPath = flag.String("db", "lanternis.db", "SQLite database path")
		debug  = flag.Bool("debug", false, "verbose logs: per-IP probes, passive collected/in_cidr/merged, scan progress ([debug] prefix)")
		bgPass = flag.Duration("background-passive-interval", 0,
			"run SSDP/mDNS in the background on this period (0 = off; e.g. 1m). Uses Suggested CIDR after first-run setup.")
		bgWin = flag.Duration("background-passive-window", 10*time.Second,
			"listen duration for each background SSDP and mDNS pass (they run in parallel each tick)")
	)
	flag.Parse()

	logger := log.New(os.Stdout, "lanternis ", log.LstdFlags|log.Lmsgprefix)
	if *debug {
		logger.Printf("debug logging enabled (-debug); look for [debug] lines")
	}
	ctx := context.Background()

	st, err := store.Open(ctx, *dbPath)
	if err != nil {
		logger.Fatalf("open store: %v", err)
	}
	defer st.Close()

	scanner := discovery.NewScanner()
	srv := httpserver.New(logger, st, scanner, httpserver.Config{
		DBPath:  *dbPath,
		Version: version,
		Debug:   *debug,
	})

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	bgCtx, bgCancel := context.WithCancel(context.Background())
	defer bgCancel()
	go srv.RunBackgroundPassive(bgCtx, httpserver.BackgroundPassiveConfig{
		Interval: *bgPass,
		Window:   *bgWin,
	})
	if *bgPass > 0 {
		logger.Printf("background passive: interval=%v window=%v (SSDP+mDNS in parallel each tick)", *bgPass, *bgWin)
	}

	go func() {
		logger.Printf("serving http://%s", *addr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("http server: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	bgCancel()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		logger.Printf("shutdown error: %v", err)
	}
}
