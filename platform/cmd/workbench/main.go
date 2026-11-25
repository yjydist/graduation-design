package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"grad/platform/bootstrap"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := newCommand().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newCommand() *cobra.Command {
	var config string
	cmd := &cobra.Command{
		Use:           "workbench",
		Short:         "Run one domain's browser workbench",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return serve(cmd.Context(), config)
		},
	}
	cmd.CompletionOptions.DisableDefaultCmd = true
	cmd.Flags().StringVar(&config, "config", "", "Path to local domain JSON configuration")
	_ = cmd.MarkFlagRequired("config")

	var fabricPath, output string
	prepare := &cobra.Command{
		Use:   "prepare",
		Short: "Provision an isolated Fabric deployment for the three workbenches",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return bootstrap.PrepareWorkbench(cmd.Context(), fabricPath, output)
		},
	}
	prepare.Flags().StringVar(&fabricPath, "fabric", "", "Directory of the running isolated Fabric deployment")
	prepare.Flags().StringVar(&output, "output", "", "Directory for per-domain configuration and secrets")
	_ = prepare.MarkFlagRequired("fabric")
	_ = prepare.MarkFlagRequired("output")
	cmd.AddCommand(prepare)
	return cmd
}

func serve(ctx context.Context, config string) error {
	app, err := bootstrap.StartWorkbench(ctx, config)
	if err != nil {
		return err
	}
	defer app.Close()

	browser := newHTTPServer(app.BrowserAddr, app.Browser)
	listener, err := net.Listen("tcp", browser.Addr)
	if err != nil {
		return fmt.Errorf("browser listener: %w", err)
	}
	defer listener.Close()

	var internal *http.Server
	results := make(chan error, 2)
	if app.InternalAddr != "" {
		if app.Internal == nil || app.InternalTLS == nil || app.InternalTLS.ClientAuth != tls.RequireAndVerifyClientCert {
			return errors.New("the internal listener requires mutually authenticated TLS")
		}
		internal = newHTTPServer(app.InternalAddr, app.Internal)
		internal.TLSConfig = app.InternalTLS
		internalListener, err := net.Listen("tcp", internal.Addr)
		if err != nil {
			return fmt.Errorf("internal listener: %w", err)
		}
		defer internalListener.Close()
		go func() { results <- internal.ServeTLS(internalListener, "", "") }()
	}
	go func() { results <- browser.Serve(listener) }()

	select {
	case err = <-results:
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = errors.Join(err, browser.Shutdown(shutdown))
	if internal != nil {
		err = errors.Join(err, internal.Shutdown(shutdown))
	}
	return err
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
}
