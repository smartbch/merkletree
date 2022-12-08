package merkletree

import (
	"bytes"
	"errors"
	"golang.org/x/crypto/sha3"
	"hash"
	"sort"
)

// Content represents the data that is stored and verified by the tree. A type that
// implements this interface can be used as an item in the tree.
type Content interface {
	CalculateHash() ([]byte, error)
	Equals(other Content) (bool, error)
}

// MerkleTree is the container for the tree. It holds a pointer to the root of the tree,
// a list of pointers to the leaf nodes, and the merkle root.
type MerkleTree struct {
	Root         *Node
	merkleRoot   []byte
	Leafs        []*Node
	hashStrategy func() hash.Hash
}

type Node struct {
	Tree   *MerkleTree
	Parent *Node
	Left   *Node
	Right  *Node
	leaf   bool
	single bool
	Hash   []byte
	C      Content
}

func (n *Node) verifyNode() ([]byte, error) {
	if n.leaf {
		return n.C.CalculateHash()
	}

	rightBytes, err := n.Right.verifyNode()
	if err != nil {
		return nil, err
	}

	leftBytes, err := n.Left.verifyNode()
	if err != nil {
		return nil, err
	}

	// if have only one child
	if n.Left == n.Right && n.Left.single && n.Right.single {
		return n.Hash, nil
	}

	h := n.Tree.hashStrategy()
	if _, err := h.Write(combineTwoHash(leftBytes, rightBytes)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func (n *Node) calculateNodeHash() ([]byte, error) {
	if n.leaf {
		return n.C.CalculateHash()
	}

	// if n is single or n's child is single
	if n.single || (n.Left == n.Right && n.Left.single && n.Right.single) {
		return n.Hash, nil
	}

	h := n.Tree.hashStrategy()
	if _, err := h.Write(combineTwoHash(n.Left.Hash, n.Right.Hash)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func NewTree(cs []Content) (*MerkleTree, error) {
	// default hash is keccak256
	return NewTreeWithHashStrategy(cs, sha3.NewLegacyKeccak256)
}

func NewTreeWithHashStrategy(cs []Content, hashStrategy func() hash.Hash) (*MerkleTree, error) {
	t := &MerkleTree{
		hashStrategy: hashStrategy,
	}
	root, leafs, err := buildWithContent(cs, t)
	if err != nil {
		return nil, err
	}
	t.Root = root
	t.Leafs = leafs
	t.merkleRoot = root.Hash
	return t, nil
}

func (m *MerkleTree) GetMerklePath(content Content) ([][]byte, []int64, error) {
	for _, current := range m.Leafs {
		ok, err := current.C.Equals(content)
		if err != nil {
			return nil, nil, err
		}

		if ok {
			currentParent := current.Parent
			var merklePath [][]byte
			var index []int64
			for currentParent != nil {
				if !current.single {
					if bytes.Equal(currentParent.Left.Hash, current.Hash) {
						merklePath = append(merklePath, currentParent.Right.Hash)
						index = append(index, 1) // right leaf
					} else {
						merklePath = append(merklePath, currentParent.Left.Hash)
						index = append(index, 0) // left leaf
					}
				}

				current = currentParent
				currentParent = currentParent.Parent
			}
			return merklePath, index, nil
		}
	}
	return nil, nil, nil
}

func buildWithContent(cs []Content, t *MerkleTree) (*Node, []*Node, error) {
	if len(cs) == 0 {
		return nil, nil, errors.New("error: cannot construct tree with no content")
	}
	var leafs []*Node
	for _, c := range cs {
		hashBz, err := c.CalculateHash()
		if err != nil {
			return nil, nil, err
		}

		leafs = append(leafs, &Node{
			Hash: hashBz,
			C:    c,
			leaf: true,
			Tree: t,
		})
	}

	leafs = sortLeafs(leafs)
	root, err := buildIntermediate(leafs, t)
	if err != nil {
		return nil, nil, err
	}

	return root, leafs, nil
}

func sortLeafs(leafs []*Node) []*Node {
	sort.Slice(leafs, func(i, j int) bool {
		return bytes.Compare(leafs[i].Hash, leafs[j].Hash) < 0
	})
	return leafs
}

func buildIntermediate(nl []*Node, t *MerkleTree) (*Node, error) {
	var nodes []*Node
	for i := 0; i < len(nl); i += 2 {
		h := t.hashStrategy()
		var left, right = i, i + 1
		if i+1 == len(nl) {
			right = i
		}

		var nextHash []byte
		if left != right {
			// appear in pairs
			// compare their child hashes when doing combine
			if _, err := h.Write(combineTwoHash(nl[left].Hash, nl[right].Hash)); err != nil {
				return nil, err
			}
			nextHash = h.Sum(nil)
		} else {
			// single node
			// don't compute new hash
			nextHash = nl[right].Hash
			nl[right].single = true
		}

		n := &Node{
			Left:  nl[left],
			Right: nl[right],
			Hash:  nextHash,
			Tree:  t,
		}
		nodes = append(nodes, n)
		nl[left].Parent = n
		nl[right].Parent = n
		if len(nl) == 2 || len(nl) == 1 {
			// n is root
			return n, nil
		}
	}
	return buildIntermediate(nodes, t)
}

func (m *MerkleTree) MerkleRoot() []byte {
	return m.merkleRoot
}

func (m *MerkleTree) RebuildTree() error {
	var cs []Content
	for _, c := range m.Leafs {
		cs = append(cs, c.C)
	}
	root, leafs, err := buildWithContent(cs, m)
	if err != nil {
		return err
	}
	m.Root = root
	m.Leafs = leafs
	m.merkleRoot = root.Hash
	return nil
}

func (m *MerkleTree) RebuildTreeWith(cs []Content) error {
	root, leafs, err := buildWithContent(cs, m)
	if err != nil {
		return err
	}
	m.Root = root
	m.Leafs = leafs
	m.merkleRoot = root.Hash
	return nil
}

func (m *MerkleTree) VerifyContent(content Content) (bool, error) {
	for _, current := range m.Leafs {
		ok, err := current.C.Equals(content)
		if err != nil {
			return false, err
		}

		if ok {
			currentParent := current.Parent
			for currentParent != nil {
				if !current.single {
					h := m.hashStrategy()
					rightHash, err := currentParent.Right.calculateNodeHash()
					if err != nil {
						return false, err
					}

					leftHash, err := currentParent.Left.calculateNodeHash()
					if err != nil {
						return false, err
					}

					if _, err := h.Write(combineTwoHash(leftHash, rightHash)); err != nil {
						return false, err
					}
					calHash := h.Sum(nil)
					if bytes.Compare(calHash, currentParent.Hash) != 0 {
						return false, nil
					}
				}

				current = currentParent
				currentParent = currentParent.Parent
			}
			return true, nil
		}
	}
	return false, nil
}

func (m *MerkleTree) VerifyTree() (bool, error) {
	calculatedMerkleRoot, err := m.Root.verifyNode()
	if err != nil {
		return false, err
	}

	if bytes.Compare(m.merkleRoot, calculatedMerkleRoot) == 0 {
		return true, nil
	}
	return false, nil
}

// ----------------------------------------------------------------------------

func combineTwoHash(a, b []byte) []byte {
	bf := bytes.NewBuffer(nil)
	if bytes.Compare(a, b) < 0 {
		bf.Write(a)
		bf.Write(b)
		return bf.Bytes()
	}

	bf.Write(b)
	bf.Write(a)
	return bf.Bytes()
}
