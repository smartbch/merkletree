package merkletree

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

type TestLeaf struct {
	Bz []byte
}

// CalculateHash hashes the values of a Leaf
func (l TestLeaf) CalculateHash() ([]byte, error) {
	h := gethcrypto.NewKeccakState()
	if _, err := h.Write(l.Bz); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// Equals tests for equality of two Contents
func (l TestLeaf) Equals(other Content) (bool, error) {
	return bytes.Equal(l.Bz, other.(TestLeaf).Bz), nil
}

// TODO: add more unit tests for merkle tree
func Test_Example(t *testing.T) {
	var leaves []Content

	l1, _ := hexutil.Decode("0x0ea2f6db280907a6e5080d8266d65c047ce3a6c8357ad0f9af40320590b4b476e66ce4a2e0d1d88e8c8b4c072b05382b52ddbeeceae4cc9f39ef54ca097b12c1")
	l2, _ := hexutil.Decode("0xc7f48d5a54e2d84f0f1ef8e7f3b8f90f71e1d13fab6bc3e6380849076a9cee3fdf63589b9583a7ccc42f547469494dde13a65833caabc96278aad26a15383689")
	l3, _ := hexutil.Decode("0x9d596229cb1f3ace0135273d1f973f6b76b536b46c628aaedbb967e2711a4dc1d462ef288dd04b4b1fd49bda2f74c794c4f949a070133dc145fba0ac2ec83082")
	l4, _ := hexutil.Decode("0x30e71bff0e52e6a042c182ac2ca5e68496de17cae53ebf49ba63404379e577183d3018f79ccc5c14aa48487c25934dd3444a247d1581bc23f9117a97825e7a70")

	leaves = append(leaves, TestLeaf{Bz: l1})
	leaves = append(leaves, TestLeaf{Bz: l2})
	leaves = append(leaves, TestLeaf{Bz: l3})
	leaves = append(leaves, TestLeaf{Bz: l4})

	tree, _ := NewTreeWithHashStrategy(leaves, sha3.NewLegacyKeccak256)
	for _, leaf := range tree.Leafs {
		fmt.Printf("leaf hash: %v\n", hexutil.Encode(leaf.Hash))
	}
	fmt.Printf("root hash: %s\n", hexutil.Encode(tree.MerkleRoot()))

	path, i, _ := tree.GetMerklePath(leaves[3])
	fmt.Printf("path: %v\n", path)
	fmt.Printf("index: %v\n", i)

	verifyContent, _ := tree.VerifyContent(leaves[3])
	fmt.Printf("verifyContent: %v\n", verifyContent)

	verifyTree, _ := tree.VerifyTree()
	fmt.Printf("verifyTree: %v\n", verifyTree)
}
