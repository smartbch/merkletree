package merkletree

import (
	"bytes"
	"fmt"
	"testing"

	gethcmn "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

type Leaf struct {
	Bz []byte
}

// CalculateHash hashes the values of a Leaf
func (l Leaf) CalculateHash() ([]byte, error) {
	h := gethcrypto.NewKeccakState()
	if _, err := h.Write(l.Bz); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// Equals tests for equality of two Contents
func (l Leaf) Equals(other Content) (bool, error) {
	return bytes.Equal(l.Bz, other.(Leaf).Bz), nil
}

// TODO: add more unit tests for merkle tree
func Test_Example(t *testing.T) {
	var list []Content
	list = append(list, Leaf{Bz: gethcmn.FromHex("0x0e")})
	list = append(list, Leaf{Bz: gethcmn.FromHex("0x0d")})
	list = append(list, Leaf{Bz: gethcmn.FromHex("0x0c")})
	list = append(list, Leaf{Bz: gethcmn.FromHex("0x0b")})
	list = append(list, Leaf{Bz: gethcmn.FromHex("0x0a")})

	tree, _ := NewTreeWithHashStrategy(list, sha3.NewLegacyKeccak256)
	for _, leaf := range tree.Leafs {
		fmt.Printf("leaf hash: %v\n", hexutil.Encode(leaf.Hash))
	}
	fmt.Printf("root hash: %s\n", hexutil.Encode(tree.MerkleRoot()))

	path, i, _ := tree.GetMerklePath(list[4])
	fmt.Printf("path: %v\n", path)
	fmt.Printf("index: %v\n", i)

	verifyContent, _ := tree.VerifyContent(list[2])
	fmt.Printf("verifyContent: %v\n", verifyContent)

	verifyTree, _ := tree.VerifyTree()
	fmt.Printf("verifyTree: %v\n", verifyTree)
}
