/*
KryxAI - reports anchor chaincode (Hyperledger Fabric 2.x)

Pattern-consistent with NBF-Lite's fabcar.go: a minimal CRUD chaincode over a
single `ReportAnchor` asset. Invoked by the KryxAI backend through an
NBF-samplerest-compatible REST gateway (deploy/nbf-fabric/gateway).

Asset (reportAnchor):

	scan_id, report_id, case_id, file_sha256, merkle_root, block_hash,
	timestamp, ipfs_cid, enc_alg, key_fp

Data-privacy note: only hashes/CID/fingerprint are stored on the ledger. The
AES-256-GCM ciphertext lives on IPFS only, under operator custody. A mail
capture is never uploaded here: `file_sha256` is the digest of the capture
file, and the capture content itself stays with the operator.
*/
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SmartContract provides the anchorReport read/write functions.
type SmartContract struct {
	contractapi.Contract
}

// ReportAnchor is an on-ledger record binding a KryxAI report block to a
// hash/IPFS-ciphertext/fingerprint record.
type ReportAnchor struct {
	ScanID         string `json:"scan_id"`
	ReportID       string `json:"report_id"`
	CaseID         string `json:"case_id"`
	FileSHA256     string `json:"file_sha256"`
	MerkleRoot     string `json:"merkle_root"`
	BlockHash      string `json:"block_hash"`
	Timestamp      string `json:"timestamp"`
	IPFSCID        string `json:"ipfs_cid"`
	EncAlg         string `json:"enc_alg"`
	KeyFingerprint string `json:"key_fp"`
}

// keyFor derives a deterministic unique key from scan id + block hash slice.
func keyFor(scanID, blockHash string) string {
	suffix := blockHash
	if len(blockHash) > 12 {
		suffix = blockHash[:12]
	}
	return "anchor-" + suffix + "-" + scanID
}

// InitLedger seeds a genesis anchor so chain lookups have a stable origin.
func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	b, err := json.Marshal(ReportAnchor{
		ScanID: "genesis", ReportID: "GENESIS", CaseID: "", FileSHA256: "-",
		MerkleRoot: "-", BlockHash: "genesis", Timestamp: "1970-01-01T00:00:00Z",
		IPFSCID: "QmGenesisPlaceholder", EncAlg: "-", KeyFingerprint: "-",
	})
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState("anchor-genesis", b)
}

// AnchorReport records an external anchor for a KryxAI report block.
// Args (order matches the backend's I4CAnchor._fabric_invoke):
//
//	0 scan_id 1 report_id 2 case_id 3 file_sha256 4 merkle_root
//	5 block_hash 6 timestamp 7 ipfs_cid 8 enc_alg 9 key_fp
func (s *SmartContract) AnchorReport(
	ctx contractapi.TransactionContextInterface,
	scanID, reportID, caseID, fileSHA256, merkleRoot, blockHash, timestamp, ipfsCID, encAlg, keyFingerprint string,
) error {
	rec := ReportAnchor{
		ScanID:         scanID,
		ReportID:       reportID,
		CaseID:         caseID,
		FileSHA256:     fileSHA256,
		MerkleRoot:     merkleRoot,
		BlockHash:      blockHash,
		Timestamp:      timestamp,
		IPFSCID:        ipfsCID,
		EncAlg:         encAlg,
		KeyFingerprint: keyFingerprint,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return ctx.GetStub().PutState(keyFor(scanID, blockHash), b)
}

// QueryReport returns the anchor record for a scan id.
func (s *SmartContract) QueryReport(ctx contractapi.TransactionContextInterface, scanID string) (*ReportAnchor, error) {
	iter, err := ctx.GetStub().GetStateByRange("anchor-", "anchor.")
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var rec ReportAnchor
		if err := json.Unmarshal(kv.Value, &rec); err != nil {
			continue
		}
		if rec.ScanID == scanID {
			return &rec, nil
		}
	}
	return nil, fmt.Errorf("no anchor for scan %q", scanID)
}

// QueryAll returns every stored anchor record.
func (s *SmartContract) QueryAll(ctx contractapi.TransactionContextInterface) ([]ReportAnchor, error) {
	iter, err := ctx.GetStub().GetStateByRange("anchor-", "anchor.")
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	out := []ReportAnchor{}
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var rec ReportAnchor
		if err := json.Unmarshal(kv.Value, &rec); err == nil {
			out = append(out, rec)
		}
	}
	return out, nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(new(SmartContract))
	if err != nil {
		fmt.Printf("Error creating KryxAI anchors chaincode: %s", err)
		return
	}

	// Chaincode-as-a-service mode (no Docker): run the contract as a standalone
	// gRPC server the peer connects to (deploy/nbf-fabric/render/Dockerfile).
	// Falls back to the classic in-process launch when the env var is unset.
	if addr := os.Getenv("CHAINCODE_SERVER_ADDRESS"); addr != "" {
		ccid := os.Getenv("CORE_CHAINCODE_ID_NAME")
		if ccid == "" {
			ccid = "kryxai-posture_1.0"
		}
		server := &shim.ChaincodeServer{
			CCID:     ccid,
			Address:  addr,
			CC:       chaincode,
			TLSProps: shim.TLSProperties{Disabled: true},
		}
		if err := server.Start(); err != nil {
			fmt.Printf("Error starting KryxAI anchors chaincode server: %s", err)
		}
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting KryxAI anchors chaincode: %s", err)
	}
}
