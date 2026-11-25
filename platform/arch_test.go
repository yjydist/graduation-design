package platform_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const (
	platformModule    = "grad/platform"
	experimentsModule = "grad/experiments"
)

// archLayer classifies a package path relative to platform/ into one of the
// five-layer architecture zones.
type archLayer string

const (
	layerRoot         archLayer = "root"
	layerInternal     archLayer = "internal"
	layerCoreDAO      archLayer = "core/dao"
	layerCoreLedger   archLayer = "core/ledger"
	layerCoreDomain   archLayer = "core/domain"
	layerServiceAPI   archLayer = "service/api"
	layerServiceMCP   archLayer = "service/mcp"
	layerAgent        archLayer = "agent"
	layerBootstrap    archLayer = "bootstrap"
	layerCmd          archLayer = "cmd"
	layerLegacyOrUnkn archLayer = "legacy/unknown"
)

type archFileSpec struct {
	RelPath         string   // path relative to platform/, slash-separated
	PkgRel          string   // package dir relative to platform/, "" for root
	IsTest          bool     // true if *_test.go
	Imports         []string // quoted import paths stripped of quotes
	HTTPServerCalls []string // forbidden net/http server/router selectors
}

// classifyPackage maps a directory path relative to platform/ (slash-separated)
// to its architectural layer.
func classifyPackage(pkgRel string) archLayer {
	pkgRel = strings.Trim(filepath.ToSlash(pkgRel), "/")
	switch {
	case pkgRel == "" || pkgRel == ".":
		return layerRoot
	case pkgRel == "internal" || strings.HasPrefix(pkgRel, "internal/"):
		return layerInternal
	case pkgRel == "core/dao" || strings.HasPrefix(pkgRel, "core/dao/"):
		return layerCoreDAO
	case pkgRel == "core/ledger" || strings.HasPrefix(pkgRel, "core/ledger/"):
		return layerCoreLedger
	case pkgRel == "core/domain" || strings.HasPrefix(pkgRel, "core/domain/"):
		return layerCoreDomain
	case pkgRel == "service/api" || strings.HasPrefix(pkgRel, "service/api/"):
		return layerServiceAPI
	case pkgRel == "service/mcp" || strings.HasPrefix(pkgRel, "service/mcp/"):
		return layerServiceMCP
	case pkgRel == "agent" || strings.HasPrefix(pkgRel, "agent/"):
		return layerAgent
	case pkgRel == "bootstrap" || strings.HasPrefix(pkgRel, "bootstrap/"):
		return layerBootstrap
	case pkgRel == "cmd" || strings.HasPrefix(pkgRel, "cmd/"):
		return layerCmd
	default:
		return layerLegacyOrUnkn
	}
}

func hasImportPrefix(imp, prefix string) bool {
	return imp == prefix || strings.HasPrefix(imp, prefix+"/")
}

func hasAnyPrefix(imp string, prefixes ...string) bool {
	for _, p := range prefixes {
		if hasImportPrefix(imp, p) {
			return true
		}
	}
	return false
}

var (
	llmSDKPrefixes = []string{
		"github.com/openai/openai-go",
		"github.com/anthropics/anthropic-sdk-go",
	}
	pgxPrefixes = []string{
		"github.com/jackc/pgx/v5",
		"github.com/pressly/goose/v3",
	}
	fabricPrefixes = []string{
		"github.com/hyperledger/fabric-gateway",
		"github.com/hyperledger/fabric-protos-go-apiv2",
	}
	mcpPrefixes = []string{
		"github.com/modelcontextprotocol/go-sdk",
	}
	opaPrefixes = []string{
		"github.com/open-policy-agent/opa",
	}
	// forbiddenHTTPServerSelectors detects inbound HTTP server/router coupling
	// inside L2 core/domain packages. Outbound HTTP clients (http.Client,
	// http.NewRequestWithContext, etc.) in core/domain/wallet are explicitly
	// permitted and excluded from this list.
	forbiddenHTTPServerSelectors = map[string]bool{
		"ServeMux":          true,
		"NewServeMux":       true,
		"Handle":            true,
		"HandleFunc":        true,
		"ListenAndServe":    true,
		"ListenAndServeTLS": true,
		"Server":            true,
		"ResponseWriter":    true,
	}
)

// checkFileArchitecture validates a single parsed Go file against the
// five-layer unidirectional dependency rules.
func checkFileArchitecture(f archFileSpec) []string {
	var violations []string
	layer := classifyPackage(f.PkgRel)

	addViolation := func(msg string) {
		violations = append(violations, f.RelPath+": "+msg)
	}

	if layer == layerLegacyOrUnkn {
		addViolation("package outside five-layer layout (" + f.PkgRel + ")")
		return violations
	}

	for _, imp := range f.Imports {
		// Global rule: grad/platform must never depend on grad/experiments.
		if hasImportPrefix(imp, experimentsModule) {
			addViolation("forbidden reverse dependency on " + imp)
		}
		// Global rule: production code outside internal/testutil must not import net/http/httptest.
		if !f.IsTest && f.PkgRel != "internal/testutil" && imp == "net/http/httptest" {
			addViolation("production code must not import " + imp)
		}

		switch layer {
		case layerInternal:
			if hasAnyPrefix(imp,
				platformModule+"/core/domain",
				platformModule+"/service",
				platformModule+"/agent",
				platformModule+"/bootstrap",
				platformModule+"/cmd",
			) {
				addViolation("internal package must not import upper layer " + imp)
			}

		case layerCoreDAO:
			if hasAnyPrefix(imp,
				platformModule+"/core/domain",
				platformModule+"/service",
				platformModule+"/agent",
				platformModule+"/bootstrap",
				platformModule+"/cmd",
			) {
				addViolation("L2 core/dao must not import " + imp)
			}
			// Root core/dao must stay below core/ledger; core/dao/central may
			// import core/ledger solely to satisfy ledger.StateSource.
			if f.PkgRel == "core/dao" && hasImportPrefix(imp, platformModule+"/core/ledger") {
				addViolation("L2 core/dao root must not import " + imp)
			}
			if hasAnyPrefix(imp, fabricPrefixes...) ||
				hasAnyPrefix(imp, llmSDKPrefixes...) ||
				hasAnyPrefix(imp, mcpPrefixes...) ||
				hasAnyPrefix(imp, opaPrefixes...) {
				addViolation("L2 core/dao must not import " + imp)
			}

		case layerCoreLedger:
			if hasAnyPrefix(imp,
				platformModule+"/core/domain",
				platformModule+"/service",
				platformModule+"/agent",
				platformModule+"/bootstrap",
				platformModule+"/cmd",
			) {
				addViolation("L2 core/ledger must not import " + imp)
			}
			if hasAnyPrefix(imp, llmSDKPrefixes...) ||
				hasAnyPrefix(imp, mcpPrefixes...) ||
				hasAnyPrefix(imp, opaPrefixes...) {
				addViolation("L2 core/ledger must not import " + imp)
			}

		case layerCoreDomain:
			if hasAnyPrefix(imp,
				platformModule+"/service",
				platformModule+"/agent",
				platformModule+"/bootstrap",
				platformModule+"/cmd",
			) {
				addViolation("L2 core/domain must not import upper layer " + imp)
			}
			if hasAnyPrefix(imp, llmSDKPrefixes...) ||
				hasAnyPrefix(imp, mcpPrefixes...) ||
				hasAnyPrefix(imp, fabricPrefixes...) {
				addViolation("L2 core/domain must not import " + imp)
			}
			if hasImportPrefix(f.PkgRel, "core/domain/gateway") &&
				hasImportPrefix(imp, platformModule+"/core/domain/wallet") {
				addViolation("L2 core/domain/gateway must not import " + imp)
			}
			if hasImportPrefix(f.PkgRel, "core/domain/wallet") &&
				hasImportPrefix(imp, platformModule+"/core/domain/gateway") {
				addViolation("L2 core/domain/wallet must not import " + imp)
			}

		case layerServiceAPI:
			if hasAnyPrefix(imp,
				platformModule+"/agent",
				platformModule+"/bootstrap",
				platformModule+"/cmd",
			) {
				addViolation("L3 service/api must not import upper/wiring layer " + imp)
			}
			if hasAnyPrefix(imp, llmSDKPrefixes...) || hasAnyPrefix(imp, fabricPrefixes...) {
				addViolation("L3 service/api must not import " + imp)
			}
			if !f.IsTest {
				if hasAnyPrefix(imp,
					platformModule+"/core/dao",
					platformModule+"/core/ledger",
				) {
					addViolation("L3 service/api production code must call core/domain instead of " + imp)
				}
				if hasAnyPrefix(imp, pgxPrefixes...) {
					addViolation("L3 service/api production code must not import database driver " + imp)
				}
			}

		case layerServiceMCP:
			if hasAnyPrefix(imp,
				platformModule+"/agent",
				platformModule+"/bootstrap",
				platformModule+"/cmd",
				platformModule+"/service/api",
			) {
				addViolation("L3 service/mcp must not import " + imp)
			}
			if hasAnyPrefix(imp, llmSDKPrefixes...) || hasAnyPrefix(imp, fabricPrefixes...) {
				addViolation("L3 service/mcp must not import " + imp)
			}
			if !f.IsTest {
				if hasAnyPrefix(imp,
					platformModule+"/core/dao",
					platformModule+"/core/ledger",
				) {
					addViolation("L3 service/mcp production code must call core/domain instead of " + imp)
				}
				if hasAnyPrefix(imp, pgxPrefixes...) {
					addViolation("L3 service/mcp production code must not import database driver " + imp)
				}
			}

		case layerAgent:
			if hasAnyPrefix(imp,
				platformModule+"/core",
				platformModule+"/service/api",
				platformModule+"/bootstrap",
				platformModule+"/cmd",
				platformModule+"/internal/testutil",
			) {
				addViolation("L4 agent must not import " + imp)
			}
			if hasAnyPrefix(imp, pgxPrefixes...) ||
				hasAnyPrefix(imp, fabricPrefixes...) ||
				hasAnyPrefix(imp, opaPrefixes...) {
				addViolation("L4 agent must not import infrastructure package " + imp)
			}

		case layerBootstrap:
			if hasImportPrefix(imp, platformModule+"/cmd") {
				addViolation("bootstrap must not import " + imp)
			}

		case layerCmd:
			// L5 cmd may wire bootstrap, service, agent, and public domain/ledger helpers.
		}
	}

	// L2 core/domain production files must never register inbound HTTP routes or handlers.
	if layer == layerCoreDomain && !f.IsTest {
		for _, sel := range f.HTTPServerCalls {
			addViolation("L2 core/domain must not use inbound HTTP server construct " + sel)
		}
	}

	return violations
}

func scanPlatformFiles(root string) ([]archFileSpec, error) {
	fset := token.NewFileSet()
	var specs []archFileSpec

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			name := d.Name()
			if strings.HasPrefix(name, ".") || name == "vendor" || name == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relSlash := filepath.ToSlash(rel)
		pkgRel := filepath.ToSlash(filepath.Dir(rel))
		if pkgRel == "." {
			pkgRel = ""
		}

		parsed, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}

		var imports []string
		httpAliases := map[string]bool{}
		for _, spec := range parsed.Imports {
			unquoted, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			imports = append(imports, unquoted)
			if unquoted == "net/http" {
				alias := "http"
				if spec.Name != nil {
					alias = spec.Name.Name
				}
				if alias != "_" && alias != "." {
					httpAliases[alias] = true
				}
			}
		}

		var serverCalls []string
		if len(httpAliases) > 0 {
			seen := map[string]bool{}
			ast.Inspect(parsed, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				ident, ok := sel.X.(*ast.Ident)
				if !ok || !httpAliases[ident.Name] {
					return true
				}
				if forbiddenHTTPServerSelectors[sel.Sel.Name] {
					call := "http." + sel.Sel.Name
					if !seen[call] {
						seen[call] = true
						serverCalls = append(serverCalls, call)
					}
				}
				return true
			})
			sort.Strings(serverCalls)
		}

		specs = append(specs, archFileSpec{
			RelPath:         relSlash,
			PkgRel:          pkgRel,
			IsTest:          strings.HasSuffix(d.Name(), "_test.go"),
			Imports:         imports,
			HTTPServerCalls: serverCalls,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(specs, func(i, j int) bool {
		return specs[i].RelPath < specs[j].RelPath
	})
	return specs, nil
}

func TestArchRulesEngine(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		spec      archFileSpec
		wantError bool
	}{
		{
			name: "agent importing core/domain is rejected",
			spec: archFileSpec{
				RelPath: "agent/orchestrator/flow.go",
				PkgRel:  "agent/orchestrator",
				Imports: []string{"grad/platform/core/domain/wallet"},
			},
			wantError: true,
		},
		{
			name: "agent test importing pgxpool is rejected",
			spec: archFileSpec{
				RelPath: "agent/orchestrator/flow_test.go",
				PkgRel:  "agent/orchestrator",
				IsTest:  true,
				Imports: []string{"github.com/jackc/pgx/v5/pgxpool"},
			},
			wantError: true,
		},
		{
			name: "agent importing official mcp and llm sdk is allowed",
			spec: archFileSpec{
				RelPath: "agent/orchestrator/flow.go",
				PkgRel:  "agent/orchestrator",
				Imports: []string{
					"grad/protocol",
					"grad/platform/agent/llm",
					"github.com/modelcontextprotocol/go-sdk/mcp",
				},
			},
			wantError: false,
		},
		{
			name: "service/api production importing pgxpool is rejected",
			spec: archFileSpec{
				RelPath: "service/api/gateway/server.go",
				PkgRel:  "service/api/gateway",
				Imports: []string{"github.com/jackc/pgx/v5/pgxpool"},
			},
			wantError: true,
		},
		{
			name: "service/api importing core/domain is allowed",
			spec: archFileSpec{
				RelPath: "service/api/gateway/server.go",
				PkgRel:  "service/api/gateway",
				Imports: []string{
					"net/http",
					"grad/protocol",
					"grad/platform/core/domain/gateway",
					"grad/platform/internal/httpx",
				},
			},
			wantError: false,
		},
		{
			name: "service/mcp importing agent is rejected",
			spec: archFileSpec{
				RelPath: "service/mcp/server.go",
				PkgRel:  "service/mcp",
				Imports: []string{"grad/platform/agent/llm"},
			},
			wantError: true,
		},
		{
			name: "core/domain registering http.ServeMux is rejected",
			spec: archFileSpec{
				RelPath:         "core/domain/gateway/service.go",
				PkgRel:          "core/domain/gateway",
				Imports:         []string{"net/http"},
				HTTPServerCalls: []string{"http.ServeMux"},
			},
			wantError: true,
		},
		{
			name: "core/domain/wallet outbound http client is allowed",
			spec: archFileSpec{
				RelPath: "core/domain/wallet/client.go",
				PkgRel:  "core/domain/wallet",
				Imports: []string{"net/http", "grad/protocol", "grad/platform/core/dao"},
			},
			wantError: false,
		},
		{
			name: "core/domain/gateway importing core/domain/wallet is rejected",
			spec: archFileSpec{
				RelPath: "core/domain/gateway/execute.go",
				PkgRel:  "core/domain/gateway",
				Imports: []string{"grad/platform/core/domain/wallet"},
			},
			wantError: true,
		},
		{
			name: "core/domain/wallet importing core/domain/gateway is rejected",
			spec: archFileSpec{
				RelPath: "core/domain/wallet/operations.go",
				PkgRel:  "core/domain/wallet",
				Imports: []string{"grad/platform/core/domain/gateway"},
			},
			wantError: true,
		},
		{
			name: "core/dao root importing core/ledger is rejected",
			spec: archFileSpec{
				RelPath: "core/dao/tx.go",
				PkgRel:  "core/dao",
				Imports: []string{"grad/platform/core/ledger"},
			},
			wantError: true,
		},
		{
			name: "core/dao/central implementing ledger.StateSource is allowed",
			spec: archFileSpec{
				RelPath: "core/dao/central/source.go",
				PkgRel:  "core/dao/central",
				Imports: []string{"grad/platform/core/dao", "grad/platform/core/ledger"},
			},
			wantError: false,
		},
		{
			name: "production wallet code importing net/http/httptest is rejected",
			spec: archFileSpec{
				RelPath: "core/domain/wallet/client.go",
				PkgRel:  "core/domain/wallet",
				Imports: []string{"net/http", "net/http/httptest"},
			},
			wantError: true,
		},
		{
			name: "legacy top-level package is rejected",
			spec: archFileSpec{
				RelPath: "runtime/stack.go",
				PkgRel:  "runtime",
				Imports: []string{"context"},
			},
			wantError: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			violations := checkFileArchitecture(tc.spec)
			if tc.wantError && len(violations) == 0 {
				t.Fatalf("expected architecture violation, got none")
			}
			if !tc.wantError && len(violations) > 0 {
				t.Fatalf("expected no architecture violation, got: %v", violations)
			}
		})
	}
}

func TestFiveLayerArchitecture(t *testing.T) {
	t.Parallel()

	specs, err := scanPlatformFiles(".")
	if err != nil {
		t.Fatalf("scan platform files: %v", err)
	}
	if len(specs) == 0 {
		t.Fatalf("expected Go files under platform/")
	}

	var violations []string
	for _, spec := range specs {
		violations = append(violations, checkFileArchitecture(spec)...)
	}
	if len(violations) > 0 {
		t.Fatalf("five-layer architecture violations (%d):\n%s", len(violations), strings.Join(violations, "\n"))
	}
}
