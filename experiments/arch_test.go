package experiments_test

import (
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
	platformInternalPrefix = "grad/platform/internal"
	chaincodeModulePrefix  = "grad/chaincode"
)

type expFileSpec struct {
	RelPath string
	Imports []string
}

func hasImportPrefix(imp, prefix string) bool {
	return imp == prefix || strings.HasPrefix(imp, prefix+"/")
}

func checkExperimentsFileBoundary(f expFileSpec) []string {
	var violations []string
	for _, imp := range f.Imports {
		if hasImportPrefix(imp, platformInternalPrefix) {
			violations = append(violations, f.RelPath+": experiments must not import platform internal package "+imp)
		}
		if hasImportPrefix(imp, chaincodeModulePrefix) {
			violations = append(violations, f.RelPath+": experiments must not import chaincode package "+imp)
		}
	}
	return violations
}

func scanExperimentsFiles(root string) ([]expFileSpec, error) {
	fset := token.NewFileSet()
	var specs []expFileSpec

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
		parsed, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}

		var imports []string
		for _, spec := range parsed.Imports {
			unquoted, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			imports = append(imports, unquoted)
		}
		specs = append(specs, expFileSpec{
			RelPath: filepath.ToSlash(rel),
			Imports: imports,
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

func TestExperimentsImportRulesEngine(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		spec      expFileSpec
		wantError bool
	}{
		{
			name: "public platform and protocol imports are allowed",
			spec: expFileSpec{
				RelPath: "e1/driver/run.go",
				Imports: []string{"grad/protocol", "grad/platform/bootstrap", "grad/platform/core/domain/wallet"},
			},
			wantError: false,
		},
		{
			name: "platform internal import is rejected",
			spec: expFileSpec{
				RelPath: "harness/client.go",
				Imports: []string{"grad/platform/internal/mtls"},
			},
			wantError: true,
		},
		{
			name: "platform internal root import is rejected",
			spec: expFileSpec{
				RelPath: "harness/client_test.go",
				Imports: []string{"grad/platform/internal/testutil"},
			},
			wantError: true,
		},
		{
			name: "chaincode direct import is rejected",
			spec: expFileSpec{
				RelPath: "e6/driver/run.go",
				Imports: []string{"grad/chaincode/registry"},
			},
			wantError: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			violations := checkExperimentsFileBoundary(tc.spec)
			if tc.wantError && len(violations) == 0 {
				t.Fatalf("expected boundary violation, got none")
			}
			if !tc.wantError && len(violations) > 0 {
				t.Fatalf("expected no boundary violation, got: %v", violations)
			}
		})
	}
}

func TestExperimentsModuleBoundary(t *testing.T) {
	t.Parallel()

	specs, err := scanExperimentsFiles(".")
	if err != nil {
		t.Fatalf("scan experiments files: %v", err)
	}
	if len(specs) == 0 {
		t.Fatalf("expected Go files under experiments/")
	}

	var violations []string
	for _, spec := range specs {
		violations = append(violations, checkExperimentsFileBoundary(spec)...)
	}
	if len(violations) > 0 {
		t.Fatalf("experiments module boundary violations (%d):\n%s", len(violations), strings.Join(violations, "\n"))
	}
}
