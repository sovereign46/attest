package modelpackage

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
)

const directoryBatchSize = 64

type inventoryHooks struct {
	beforeDirectoryOpen func(string)
	readDirectory       func(*os.File, int) ([]os.DirEntry, error)
}

// OpenRoot ordinarily opens a leaf without O_DIRECTORY. The final /. makes
// every path component a directory lookup, so a FIFO substitution cannot block.
func openCheckpointRoot(name string, before fs.FileInfo) (*os.Root, error) {
	root, err := os.OpenRoot(name + string(os.PathSeparator) + ".")
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err == nil && !unchanged(before, opened) {
		err = fmt.Errorf("checkpoint root changed before scan")
	}
	if err == nil {
		var current fs.FileInfo
		current, err = os.Lstat(name)
		if err == nil && !unchanged(before, current) {
			err = fmt.Errorf("checkpoint root changed before scan")
		}
	}
	if err != nil {
		root.Close()
		return nil, err
	}
	return root, nil
}

// Walk unsorted bounded batches rather than fs.WalkDir/ReadDir(-1), which collect
// an entire caller-controlled directory before applying the entry limit. Only
// pending names/metadata are retained; directory depth does not retain handles.
func walkCheckpoint(root *os.Root, hooks inventoryHooks, visit func(string, fs.FileInfo) error) error {
	before, err := root.Stat(".")
	if err != nil {
		return err
	}
	if err := visit(".", before); err != nil {
		return err
	}
	type directory struct {
		name string
		info fs.FileInfo
	}
	pending := []directory{{".", before}}
	for len(pending) != 0 {
		next := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if hooks.beforeDirectoryOpen != nil {
			hooks.beforeDirectoryOpen(next.name)
		}
		err := readCheckpointDirectory(root, next.name, next.info, hooks, func(name string, info fs.FileInfo) error {
			if err := visit(name, info); err != nil {
				if err == fs.SkipDir && info.IsDir() {
					return nil
				}
				return err
			}
			if info.IsDir() {
				pending = append(pending, directory{name, info})
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func readCheckpointDirectory(root *os.Root, name string, before fs.FileInfo, hooks inventoryHooks, visit func(string, fs.FileInfo) error) error {
	dir, err := pinCheckpointDirectory(root, name)
	if err != nil {
		return err
	}
	defer dir.Close()
	opened, err := dir.Stat(".")
	if err != nil {
		return err
	}
	if !unchanged(before, opened) {
		return fmt.Errorf("checkpoint directory %q changed before enumeration", name)
	}
	// The handle is pinned and . cannot become a different filesystem object.
	file, err := dir.OpenFile(".", readOpenFlags(), 0)
	if err != nil {
		return err
	}
	defer file.Close()
	readDirectory := hooks.readDirectory
	if readDirectory == nil {
		readDirectory = (*os.File).ReadDir
	}
	for {
		batch, err := readDirectory(file, directoryBatchSize)
		if err != nil && err != io.EOF {
			return err
		}
		for _, entry := range batch {
			// DirEntry.Info may use a pathname after its directory was renamed.
			// Stat relative to the pinned directory instead.
			info, err := dir.Lstat(entry.Name())
			if err != nil {
				return err
			}
			if err := visit(path.Join(name, entry.Name()), info); err != nil {
				return err
			}
		}
		if err == io.EOF {
			break
		}
	}
	after, err := file.Stat()
	if err != nil {
		return err
	}
	current, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if !unchanged(before, after) || !unchanged(before, current) {
		return fmt.Errorf("checkpoint directory %q changed during enumeration", name)
	}
	return nil
}

func pinCheckpointDirectory(root *os.Root, name string) (*os.Root, error) {
	parent, err := root.OpenRoot(".")
	if err != nil {
		return nil, err
	}
	if name == "." {
		return parent, nil
	}
	for _, component := range strings.Split(name, "/") {
		before, err := parent.Lstat(component)
		if err != nil {
			parent.Close()
			return nil, err
		}
		child, err := pinCheckpointComponent(parent, component, before)
		parent.Close()
		if err != nil {
			return nil, err
		}
		parent = child
	}
	return parent, nil
}

func pinCheckpointComponent(parent *os.Root, name string, before fs.FileInfo) (*os.Root, error) {
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("checkpoint directory %q is a symlink or special file", name)
	}
	child, err := parent.OpenRoot(name + "/.")
	if err != nil {
		return nil, err
	}
	opened, err := child.Stat(".")
	if err == nil && !unchanged(before, opened) {
		err = fmt.Errorf("checkpoint directory %q changed before open", name)
	}
	if err == nil {
		var current fs.FileInfo
		current, err = parent.Lstat(name)
		if err == nil && !unchanged(before, current) {
			err = fmt.Errorf("checkpoint directory %q changed during open", name)
		}
	}
	if err != nil {
		child.Close()
		return nil, err
	}
	return child, nil
}
