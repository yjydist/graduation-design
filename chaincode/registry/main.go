// Registry exposes the public Fabric D0 registration operations.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	api "graduation-design/internal/fabricapi"

	"github.com/hyperledger/fabric-chaincode-go/v2/pkg/cid"
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
)

// These values are bound into the build approved by all three business MSPs.
var (
	bootstrapDigest string
	initializer     string
	probeOne        string
	probeTwo        string
)

const (
	badInput = "INVALID_STRUCTURE"
	denied   = "UNAUTHORIZED"
	stale    = "STATE_CHANGED"
	missing  = "MISSING_DEPENDENCY"
	invalid  = "INVALID_STATE"
	used     = "ID_ALREADY_USED"
)

type registry struct{}

type transaction struct {
	stub   shim.ChaincodeStubInterface
	caller api.Management
	at     time.Time
	boot   api.Bootstrap
}

func (registry) Init(shim.ChaincodeStubInterface) *pb.Response {
	return shim.Error("D0:UNAUTHORIZED")
}

func (registry) Invoke(stub shim.ChaincodeStubInterface) *pb.Response {
	method, args := stub.GetFunctionAndParameters()
	if len(args) != 1 {
		return shim.Error("D0:" + badInput)
	}
	result, err := invoke(stub, method, []byte(args[0]))
	if err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success(result)
}

func invoke(stub shim.ChaincodeStubInterface, method string, arg []byte) ([]byte, error) {
	if stub.GetChannelID() != api.Channel || len(arg) > 65536 {
		return nil, reject(badInput)
	}
	if method == "Read" {
		value, err := stub.GetState(string(arg))
		if err == nil && len(value) == 0 {
			return nil, reject(missing)
		}
		return value, err
	}
	identity, err := cid.New(stub)
	if err != nil {
		return nil, reject(denied)
	}
	msp, err := identity.GetMSPID()
	if err != nil {
		return nil, reject(denied)
	}
	cert, err := identity.GetX509Certificate()
	if err != nil || cert == nil {
		return nil, reject(denied)
	}
	ts, err := stub.GetTxTimestamp()
	if err != nil || ts.CheckValid() != nil {
		return nil, reject(badInput)
	}
	tx := transaction{stub: stub, caller: api.Management{MSPID: msp, Fingerprint: api.Digest(cert.Raw)}, at: ts.AsTime()}
	if method == "Probe" {
		// A probe has no shared business-state reads or writes.
		if tx.caller.String() != probeOne && tx.caller.String() != probeTwo {
			return nil, reject(denied)
		}
		if len(arg) != 0 {
			return nil, reject(badInput)
		}
		return nil, tx.put(api.ProbeKey(tx.caller), api.Probe{TxID: stub.GetTxID(), Identity: tx.caller})
	}
	if method == "Initialize" {
		return nil, tx.initialize(arg)
	}
	tx.boot, err = get[api.Bootstrap](stub, api.BootstrapKey)
	if err != nil {
		return nil, err
	}
	switch method {
	case "BootstrapDomain":
		err = dispatch(arg, tx.bootstrapDomain)
	case "CertifyDomain":
		err = dispatch(arg, tx.certify)
	case "SetDomainStatus":
		err = dispatch(arg, tx.setDomainStatus)
	case "RegisterIdentity":
		err = dispatch(arg, tx.registerIdentity)
	case "RegisterCredential":
		err = dispatch(arg, tx.registerCredential)
	case "RegisterTask":
		err = dispatch(arg, tx.registerTask)
	case "RegisterGrant":
		err = dispatch(arg, tx.registerGrant)
	case "RevokeGrant":
		err = dispatch(arg, tx.revoke)
	case "ReplaceGrant":
		err = dispatch(arg, tx.replace)
	default:
		err = reject(badInput)
	}
	return nil, err
}

func reject(code string) error { return errors.New("D0:" + code) }

func dispatch[T any](arg []byte, f func(T) error) error {
	var value T
	d := json.NewDecoder(bytes.NewReader(arg))
	d.DisallowUnknownFields()
	if err := d.Decode(&value); err != nil || d.Decode(new(any)) != io.EOF {
		return reject(badInput)
	}
	return f(value)
}

func get[T any](stub shim.ChaincodeStubInterface, key string) (T, error) {
	var value T
	b, err := stub.GetState(key)
	if err != nil {
		return value, err
	}
	if b == nil {
		return value, reject(missing)
	}
	return value, json.Unmarshal(b, &value)
}

func (tx transaction) put(key string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return tx.stub.PutState(key, b)
}

func (tx transaction) vacant(key string) error {
	b, err := tx.stub.GetState(key)
	if err != nil {
		return err
	}
	if b != nil {
		return reject(used)
	}
	return nil
}

func (tx transaction) bound(b api.Bound) bool { return b.DeploymentID == tx.boot.ID() }

func (tx transaction) current(i api.Interval) bool {
	return i.Current(tx.at, api.PeerTimeWindow+api.ClockError)
}

func (tx transaction) initialize(arg []byte) error {
	if tx.caller.String() != initializer {
		return reject(denied)
	}
	if api.Digest(arg) != bootstrapDigest {
		return reject(badInput)
	}
	if err := tx.vacant(api.BootstrapKey); err != nil {
		return err
	}
	return dispatch(arg, func(b api.Bootstrap) error {
		if !b.DeploymentFields.Valid() || b.Initializer != tx.caller || b.Root.Management.MSPID != "TMsp" ||
			!b.Root.Management.Valid() || !api.IsDigest(b.Root.DocumentDigest) ||
			!api.ValidAppKey(b.Root.DID, b.Root.KeyID, b.Root.PublicKey, b.Root.KeyVersion) ||
			b.TaskCreator.Domain != "A" || b.TaskCreator.Subject == "" || b.TaskCreator.Management.MSPID != "AMsp" ||
			!b.TaskCreator.Management.Valid() || !api.IsDigest(b.ResourceID) || b.ResourceOwner == "" ||
			b.ResourceManagement.MSPID != "CMsp" || !b.ResourceManagement.Valid() {
			return reject(badInput)
		}
		return tx.put(api.BootstrapKey, b)
	})
}

func main() {
	const dir = "/registry"
	ccid, err := os.ReadFile(filepath.Join(dir, "package-id"))
	if err != nil {
		log.Fatal(err)
	}
	load := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			log.Fatal(err)
		}
		return b
	}
	if !api.IsDigest(bootstrapDigest) || initializer == "" || probeOne == "" || probeTwo == "" {
		log.Fatal("missing approved chaincode build bindings")
	}
	server := shim.ChaincodeServer{
		CCID: string(bytes.TrimSpace(ccid)), Address: "0.0.0.0:9999", CC: registry{},
		TLSProps: shim.TLSProperties{Key: load("server.key"), Cert: load("server.crt")},
	}
	if err := server.Start(); err != nil {
		log.Fatal(fmt.Errorf("chaincode server: %w", err))
	}
}
