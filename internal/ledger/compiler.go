package ledger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const CompilerVersion = "0.8.30+commit.73712a01.Emscripten.clang"

type ContractArtifact struct {
	Compiler     string          `json:"compiler"`
	SourceSHA256 string          `json:"sourceSha256"`
	InputSHA256  string          `json:"inputSha256"`
	ABI          json.RawMessage `json:"abi"`
	EVM          struct {
		Bytecode struct {
			Object string `json:"object"`
		} `json:"bytecode"`
		DeployedBytecode struct {
			Object string `json:"object"`
		} `json:"deployedBytecode"`
	} `json:"evm"`
}

// Compile uses the pinned solcjs CLI and preserves its complete standard JSON output.
func Compile(ctx context.Context, contractsDir string) (*ContractArtifact, error) {
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	args := []string{"exec", "--yes", "--package=solc@0.8.30", "--", "solcjs"}
	versionCmd := exec.CommandContext(ctx, "npm", append(args, "--version")...)
	version, err := versionCmd.Output()
	if err != nil || strings.TrimSpace(string(version)) != CompilerVersion {
		return nil, fmt.Errorf("compiler version mismatch: %q: %v", version, err)
	}
	build := filepath.Join(contractsDir, "build")
	if err = os.MkdirAll(build, 0755); err != nil {
		return nil, err
	}
	input, err := os.Open(filepath.Join(contractsDir, "compiler-input.json"))
	if err != nil {
		return nil, err
	}
	defer input.Close()
	output, err := os.Create(filepath.Join(build, "compiler-output.raw"))
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "npm", append(args, "--standard-json", "--base-path", contractsDir)...)
	cmd.Stdin, cmd.Stdout = input, output
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	closeErr := output.Close()
	if runErr != nil {
		return nil, fmt.Errorf("compiler: %w: %s", runErr, stderr.String())
	}
	if closeErr != nil {
		return nil, closeErr
	}
	b, err := os.ReadFile(filepath.Join(build, "compiler-output.raw"))
	if err != nil {
		return nil, err
	}
	start := bytes.IndexByte(b, '{')
	if start < 0 {
		return nil, fmt.Errorf("compiler returned no JSON")
	}
	var result struct {
		Contracts map[string]map[string]ContractArtifact `json:"contracts"`
		Errors    []struct {
			Severity string `json:"severity"`
			Message  string `json:"formattedMessage"`
		} `json:"errors"`
	}
	if err = json.Unmarshal(b[start:], &result); err != nil {
		return nil, err
	}
	for _, e := range result.Errors {
		if e.Severity == "error" {
			return nil, fmt.Errorf("Solidity: %s", e.Message)
		}
	}
	artifact, ok := result.Contracts["AuthRegistry.sol"]["AuthRegistry"]
	if !ok || artifact.EVM.Bytecode.Object == "" {
		return nil, fmt.Errorf("AuthRegistry bytecode missing")
	}
	if len(artifact.EVM.DeployedBytecode.Object)/2 > 24576 {
		return nil, fmt.Errorf("runtime bytecode exceeds the EVM 24576-byte limit")
	}
	artifact.Compiler = CompilerVersion
	for path, dest := range map[string]*string{"AuthRegistry.sol": &artifact.SourceSHA256, "compiler-input.json": &artifact.InputSHA256} {
		b, err := os.ReadFile(filepath.Join(contractsDir, path))
		if err != nil {
			return nil, err
		}
		d := sha256.Sum256(b)
		*dest = hex.EncodeToString(d[:])
	}
	if err = writeJSON(filepath.Join(build, "AuthRegistry.json"), artifact); err != nil {
		return nil, err
	}
	if err = os.WriteFile(filepath.Join(build, "AuthRegistry.abi.json"), artifact.ABI, 0644); err != nil {
		return nil, err
	}
	if err = os.WriteFile(filepath.Join(build, "AuthRegistry.bin"), []byte(artifact.EVM.Bytecode.Object+"\n"), 0644); err != nil {
		return nil, err
	}
	return &artifact, nil
}
