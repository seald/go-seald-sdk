package sdk

import (
	"github.com/seald/go-seald-sdk/common_models"
	"github.com/ztrue/tracerr"
)

// MemoryStorage is an implementation of Database, which stores the data in memory only.
// This instance should then directly be passed to InitializeOptions.
type MemoryStorage struct {
	initialized bool
	closed      bool
}

func (f *MemoryStorage) initialize() error {
	if f.initialized {
		return tracerr.Wrap(ErrorDatabaseAlreadyInitialized)
	}
	f.initialized = true
	return nil
}

func (f *MemoryStorage) close() error {
	f.closed = true
	return nil
}

func (f *MemoryStorage) readCurrentDevice(storage *currentDeviceStorage) error {
	if f.closed {
		return tracerr.Wrap(ErrorDatabaseClosed)
	}
	storage.currentDevice = &currentDevice{}
	return nil
}

func (f *MemoryStorage) writeCurrentDevice(storage *currentDeviceStorage) error {
	if f.closed {
		return tracerr.Wrap(ErrorDatabaseClosed)
	}
	return nil
}

func (f *MemoryStorage) readContacts(storage *contactsStorage) error {
	if f.closed {
		return tracerr.Wrap(ErrorDatabaseClosed)
	}
	storage.lock.Lock()
	defer storage.lock.Unlock()
	storage.contacts = make(map[string]contact)
	return nil
}

func (f *MemoryStorage) writeContacts(storage *contactsStorage) error {
	if f.closed {
		return tracerr.Wrap(ErrorDatabaseClosed)
	}
	return nil
}

func (f *MemoryStorage) readConnectors(storage *connectorsStorage) error {
	if f.closed {
		return tracerr.Wrap(ErrorDatabaseClosed)
	}
	storage.lock.Lock()
	defer storage.lock.Unlock()
	storage.connectors = make(map[string]common_models.Connector)
	return nil
}

func (f *MemoryStorage) writeConnectors(storage *connectorsStorage) error {
	if f.closed {
		return tracerr.Wrap(ErrorDatabaseClosed)
	}
	return nil
}

func (f *MemoryStorage) readGroups(storage *groupsStorage) error {
	if f.closed {
		return tracerr.Wrap(ErrorDatabaseClosed)
	}
	storage.lock.Lock()
	defer storage.lock.Unlock()
	storage.groups = make(map[string]group)
	return nil
}

func (f *MemoryStorage) writeGroups(storage *groupsStorage) error {
	if f.closed {
		return tracerr.Wrap(ErrorDatabaseClosed)
	}
	return nil
}

func (f *MemoryStorage) readEncryptionSessions(storage *encryptionSessionCache) error {
	if f.closed {
		return tracerr.Wrap(ErrorDatabaseClosed)
	}
	storage.lock.Lock()
	defer storage.lock.Unlock()
	storage.encryptionSessions = make(map[string]encryptionSessionCacheEntry)
	return nil
}

func (f *MemoryStorage) writeEncryptionSessions(storage *encryptionSessionCache) error {
	if f.closed {
		return tracerr.Wrap(ErrorDatabaseClosed)
	}
	return nil
}
