package sdk

import (
	"github.com/ztrue/tracerr"
)

type canaryFileStorage struct {
	storage   Database
	ToExecute map[string]func() error
	Counter   map[string]int
}

func newCanaryFileStorage(storage Database) *canaryFileStorage {
	return &canaryFileStorage{storage: storage, ToExecute: make(map[string]func() error), Counter: make(map[string]int)}
}

func executeFileStorageCanary(c canaryFileStorage, funcName string) error {
	c.Counter[funcName] += 1
	if c.ToExecute[funcName] != nil {
		err := c.ToExecute[funcName]()
		if err != nil {
			return tracerr.Wrap(err)
		}
	}
	return nil
}

func (c canaryFileStorage) initialize() error {
	err := executeFileStorageCanary(c, "Initialize")
	if err != nil {
		return err
	}
	return c.storage.initialize()
}

func (c canaryFileStorage) close() error {
	err := executeFileStorageCanary(c, "Close")
	if err != nil {
		return err
	}
	return c.storage.close()
}

func (c canaryFileStorage) readCurrentDevice(storage *currentDeviceStorage) error {
	err := executeFileStorageCanary(c, "ReadCurrentDevice")
	if err != nil {
		return err
	}
	return c.storage.readCurrentDevice(storage)
}

func (c canaryFileStorage) writeCurrentDevice(storage *currentDeviceStorage) error {
	err := executeFileStorageCanary(c, "WriteCurrentDevice")
	if err != nil {
		return err
	}
	return c.storage.writeCurrentDevice(storage)
}

func (c canaryFileStorage) readContacts(contacts *contactsStorage) error {
	err := executeFileStorageCanary(c, "ReadContacts")
	if err != nil {
		return err
	}
	return c.storage.readContacts(contacts)
}

func (c canaryFileStorage) writeContacts(contacts *contactsStorage) error {
	err := executeFileStorageCanary(c, "WriteContacts")
	if err != nil {
		return err
	}
	return c.storage.writeContacts(contacts)
}

func (c canaryFileStorage) readGroups(groupDevices *groupsStorage) error {
	err := executeFileStorageCanary(c, "ReadGroups")
	if err != nil {
		return err
	}
	return c.storage.readGroups(groupDevices)
}

func (c canaryFileStorage) writeGroups(groupDevices *groupsStorage) error {
	err := executeFileStorageCanary(c, "WriteGroups")
	if err != nil {
		return err
	}
	return c.storage.writeGroups(groupDevices)
}

func (c canaryFileStorage) readConnectors(connector *connectorsStorage) error {
	err := executeFileStorageCanary(c, "ReadConnectors")
	if err != nil {
		return err
	}
	return c.storage.readConnectors(connector)
}

func (c canaryFileStorage) writeConnectors(connector *connectorsStorage) error {
	err := executeFileStorageCanary(c, "WriteConnectors")
	if err != nil {
		return err
	}
	return c.storage.writeConnectors(connector)
}

func (c canaryFileStorage) readEncryptionSessions(esc *encryptionSessionCache) error {
	err := executeFileStorageCanary(c, "ReadEncryptionSession")
	if err != nil {
		return err
	}
	return c.storage.readEncryptionSessions(esc)
}

func (c canaryFileStorage) writeEncryptionSessions(esc *encryptionSessionCache) error {
	err := executeFileStorageCanary(c, "WriteEncryptionSession")
	if err != nil {
		return err
	}
	return c.storage.writeEncryptionSessions(esc)
}
