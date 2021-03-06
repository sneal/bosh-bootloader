package vsphere

import (
	"context"
	"fmt"

	"github.com/genevieve/leftovers/aws/common"
	"github.com/vmware/govmomi/object"
)

type client interface {
	GetRootFolder(filter string) (*object.Folder, error)
}

type Folders struct {
	client client
	logger logger
}

func NewFolders(client client, logger logger) Folders {
	return Folders{
		client: client,
		logger: logger,
	}
}

func (v Folders) List(filter string) ([]common.Deletable, error) {
	root, err := v.client.GetRootFolder(filter)
	if err != nil {
		return nil, fmt.Errorf("Getting root folder: %s", err)
	}

	var deletable []common.Deletable

	ctx := context.Background()

	children, err := root.Children(ctx)
	if err != nil {
		return nil, fmt.Errorf("Root folder children: %s", err)
	}

	for _, child := range children {
		childFolder, ok := child.(*object.Folder)
		if !ok {
			continue
		}

		grandchildren, err := childFolder.Children(ctx)
		if err != nil {
			return nil, fmt.Errorf("Folder children: %s", err)
		}

		if len(grandchildren) == 0 {
			name, err := childFolder.Common.ObjectName(ctx)
			if err != nil {
				return nil, fmt.Errorf("Folder name: %s", err)
			}

			folder := NewFolder(childFolder, name)

			proceed := v.logger.Prompt(fmt.Sprintf("Are you sure you want to delete empty folder %s?", name))
			if !proceed {
				continue
			}

			deletable = append(deletable, folder)
		}
	}

	return deletable, nil
}
