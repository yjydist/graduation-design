package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/rwset"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/rwset/kvrwset"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"google.golang.org/protobuf/proto"
)

func writePublicJSON(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writePublicFile(path, append(b, '\n'))
}

func writePublicFile(path string, b []byte) error {
	if bytes.Contains(b, []byte("-----BEGIN ")) && bytes.Contains(b, []byte("PRIVATE KEY-----")) {
		return fmt.Errorf("private key in evidence file %s", filepath.Base(path))
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}

func (e *e1Trial) finish() (err error) {
	if e.did != nil {
		err = errors.Join(err, e.did.Close())
	}
	err = errors.Join(err, e.writeHTTP(), e.save("llm-traces", e.traces))
	if e.db == nil {
		return err
	}
	defer e.db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if e.sp != nil {
		err = errors.Join(err, e.exportBlocks(ctx))
	}
	if e.server != nil {
		for _, item := range []struct{ name, table, expression string }{
			{"quotes", "quotes", "to_jsonb(x)"}, {"orders", "orders", "to_jsonb(x)"}, {"decisions", "decisions", "to_jsonb(x)"},
			{"challenges", "challenges", "to_jsonb(x)-'nonce'"}, {"business-keys", "business_keys", "to_jsonb(x)"},
		} {
			var raw json.RawMessage
			query := "SELECT COALESCE(jsonb_agg(" + item.expression + " ORDER BY to_jsonb(x)), '[]'::jsonb) FROM " + item.table + " x WHERE deployment_id=$1"
			if readErr := e.db.QueryRow(ctx, query, e.d.DeploymentID).Scan(&raw); readErr != nil {
				err = errors.Join(err, readErr)
				continue
			}
			err = errors.Join(err, e.save("db-"+item.name, raw))
		}
	}
	return errors.Join(err, e.copyRunMaterials())
}

func (e *e1Trial) copyRunMaterials() error {
	top := filepath.Join(e.dir, "materials")
	for _, name := range []string{"network.env", "genesis.pb", "configtx.yaml", "cryptogen.yaml", "orderer-a.json", "orderer-b.json", "orderer-c.json", "orderer-d.json"} {
		raw, err := os.ReadFile(filepath.Join(e.instance.dir, name))
		if err != nil {
			return err
		}
		if err := writePublicFile(filepath.Join(top, name), raw); err != nil {
			return err
		}
	}
	for _, name := range []string{"deployment.json", "approval.json", "bootstrap.json", "definition.json", "initialization.json", "fixtures.json", "context-manifest.json", "vc-v2.context.json"} {
		raw, err := os.ReadFile(e.instance.registrySubPath(name))
		if err != nil {
			return err
		}
		if err := writePublicFile(filepath.Join(top, "registry", name), raw); err != nil {
			return err
		}
	}
	for _, name := range []string{"did", "certifications", "credentials", "grants", "ca"} {
		root := e.instance.registrySubPath(name)
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			if !entry.Type().IsRegular() {
				return fmt.Errorf("unexpected material: %s", entry.Name())
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return writePublicFile(filepath.Join(top, "registry", name, rel), raw)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (e *e1Trial) exportBlocks(ctx context.Context) (err error) {
	rows, err := e.db.Query(ctx, `SELECT block_no,hash,parent,data FROM fabric_block WHERE deployment=$1 ORDER BY block_no`, e.d.DeploymentID)
	if err != nil {
		return err
	}
	defer rows.Close()
	index, err := os.Create(filepath.Join(e.dir, "blocks.jsonl"))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, index.Close()) }()
	enc := json.NewEncoder(index)
	for rows.Next() {
		var p point
		var parent string
		var raw []byte
		if err := rows.Scan(&p.Number, &p.Hash, &parent, &raw); err != nil {
			return err
		}
		var block cb.Block
		if err := proto.Unmarshal(raw, &block); err != nil {
			return err
		}
		if block.Header == nil || block.Header.Number != p.Number || hex.EncodeToString(block.Header.PreviousHash) != parent {
			return fmt.Errorf("stored block %d differs from view index", p.Number)
		}
		txs, err := blockTransactions(&block)
		if err != nil {
			return fmt.Errorf("block %d transactions: %w", p.Number, err)
		}
		path := fmt.Sprintf("blocks/%06d.pb", p.Number)
		if err := writePublicFile(filepath.Join(e.dir, path), raw); err != nil {
			return err
		}
		if err := enc.Encode(map[string]any{"point": p, "parentHash": parent, "raw": path, "transactions": txs}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func blockTransactions(block *cb.Block) ([]map[string]any, error) {
	var result []map[string]any
	if block.Data == nil {
		return result, nil
	}
	var codes []byte
	if metadata := block.Metadata.GetMetadata(); len(metadata) > int(cb.BlockMetadataIndex_TRANSACTIONS_FILTER) {
		codes = metadata[cb.BlockMetadataIndex_TRANSACTIONS_FILTER]
	}
	for i, data := range block.Data.Data {
		var envelope cb.Envelope
		var payload cb.Payload
		var header cb.ChannelHeader
		if err := proto.Unmarshal(data, &envelope); err != nil {
			return nil, err
		}
		if err := proto.Unmarshal(envelope.Payload, &payload); err != nil {
			return nil, err
		}
		if err := proto.Unmarshal(payload.Header.GetChannelHeader(), &header); err != nil {
			return nil, err
		}
		if header.TxId == "" {
			continue
		}
		if i >= len(codes) {
			return nil, fmt.Errorf("missing validation code at index %d", i)
		}
		var keys []string
		if cb.HeaderType(header.Type) == cb.HeaderType_ENDORSER_TRANSACTION {
			var err error
			keys, err = registryWriteKeys(payload.Data)
			if err != nil {
				return nil, err
			}
		}
		result = append(result, map[string]any{"index": i, "txId": header.TxId, "validationCode": pb.TxValidationCode(codes[i]).String(), "writeKeys": keys})
	}
	return result, nil
}

func registryWriteKeys(data []byte) ([]string, error) {
	var tx pb.Transaction
	if err := proto.Unmarshal(data, &tx); err != nil {
		return nil, err
	}
	var keys []string
	for _, entry := range tx.Actions {
		var action pb.ChaincodeActionPayload
		var proposal pb.ProposalResponsePayload
		var chain pb.ChaincodeAction
		var result rwset.TxReadWriteSet
		if err := proto.Unmarshal(entry.Payload, &action); err != nil {
			return nil, err
		}
		if err := proto.Unmarshal(action.Action.GetProposalResponsePayload(), &proposal); err != nil {
			return nil, err
		}
		if err := proto.Unmarshal(proposal.Extension, &chain); err != nil {
			return nil, err
		}
		if err := proto.Unmarshal(chain.Results, &result); err != nil {
			return nil, err
		}
		for _, ns := range result.NsRwset {
			if ns.Namespace != "authregistry" {
				continue
			}
			var kv kvrwset.KVRWSet
			if err := proto.Unmarshal(ns.Rwset, &kv); err != nil {
				return nil, err
			}
			for _, write := range kv.Writes {
				keys = append(keys, write.Key)
			}
		}
	}
	return keys, nil
}
