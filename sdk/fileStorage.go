package sdk

import (
	"encoding/json"
	"github.com/allan-simon/go-singleinstance"
	"github.com/seald/go-seald-sdk/common_models"
	"github.com/seald/go-seald-sdk/symmetric_key"
	"github.com/seald/go-seald-sdk/utils"
	"github.com/ztrue/tracerr"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	// ErrorDatabaseLocked is returned when another instance of the Seald SDK is already using this database
	ErrorDatabaseLocked = utils.NewSealdError("DATABASE_LOCKED", "another instance of the Seald SDK is already using this database")
	// ErrorDatabaseClosed is returned when trying to use a database which is not open
	ErrorDatabaseClosed = utils.NewSealdError("DATABASE_CLOSED", "database closed")
	// ErrorDatabaseAlreadyInitialized is returned when trying to initialize a database which has already been initialized
	ErrorDatabaseAlreadyInitialized = utils.NewSealdError("DATABASE_ALREADY_INITIALIZED", "database already initialized")
)

/*
The Storage should store:
- current device details
- database of known users (including self)
- cache of EncryptionSessions and GroupKeys
*/

func readStorage[T interface{}](fileName string, key symmetric_key.SymKey, data *T) error {
	read, err := os.ReadFile(fileName)

	if err != nil {
		if os.IsNotExist(err) {
			return nil
		} else {
			return tracerr.Wrap(err)
		}
	}

	if len(read) == 0 {
		return nil
	}

	decryptedData, err := key.Decrypt(read)

	if err != nil {
		return tracerr.Wrap(err)
	}

	err = json.Unmarshal(decryptedData, &data)

	if err != nil {
		return tracerr.Wrap(err)
	}

	return nil
}

func writeStorage[T interface{}](fileName string, key symmetric_key.SymKey, data *T) error {
	marshalledData, err := json.Marshal(data)

	if err != nil {
		return tracerr.Wrap(err)
	}

	encryptedData, err := key.Encrypt(marshalledData)

	if err != nil {
		return tracerr.Wrap(err)
	}

	t := time.Now()
	// time formats are a bit esoteric ... basically, you have to write the date-time "Mon. Jan 2nd 2006 03:04:05 PM" with the format you want. And the Replace because I don't want the '.', which Format requires for milliseconds, somehow...
	now := strings.Replace(t.Format("20060102150405.000"), ".", "", 1)
	tempFileName := fileName + "_temp_" + now

	// write in 2 steps for atomic write
	err = os.WriteFile(tempFileName, encryptedData, 0600)
	if err != nil {
		return tracerr.Wrap(err)
	}

	err = os.Rename(tempFileName, fileName)
	if err != nil {
		return tracerr.Wrap(err)
	}

	return nil
}

// FileStorage is an implementation of Database, which stores the data on the File System.
// To create it, you must instantiate a FileStorage object with an EncryptionKey and DatabaseDir.
// This instance should then directly be passed to InitializeOptions.
type FileStorage struct {
	EncryptionKey              symmetric_key.SymKey
	DatabaseDir                string
	databaseLock               *os.File
	currentDeviceFileLock      sync.Mutex // these locks are for locking the file on FS, whereas the locks in each storage type is for locking the map in memory
	contactsFileLock           sync.Mutex
	connectorsFileLock         sync.Mutex
	groupsFileLock             sync.Mutex
	encryptionSessionsFileLock sync.Mutex
}

func (f *FileStorage) initialize() error {
	if f.databaseLock != nil {
		return tracerr.Wrap(ErrorDatabaseAlreadyInitialized)
	}

	err := os.MkdirAll(f.DatabaseDir, 0700)
	if err != nil {
		return tracerr.Wrap(err)
	}
	lockPath := filepath.Join(f.DatabaseDir, "lock")
	databaseLock, err := singleinstance.CreateLockFile(lockPath)
	if err != nil {
		if (runtime.GOOS == "windows" && err.Error() == "remove "+lockPath+": The process cannot access the file because it is being used by another process.") ||
			err.Error() == "resource temporarily unavailable" {
			return tracerr.Wrap(ErrorDatabaseLocked)
		} else {
			return tracerr.Wrap(err)
		}
	}
	f.databaseLock = databaseLock
	return nil
}

func (f *FileStorage) close() error {
	// ensure any writes which are already in flight finish before closing the DB
	f.currentDeviceFileLock.Lock()
	defer f.currentDeviceFileLock.Unlock()
	f.contactsFileLock.Lock()
	defer f.contactsFileLock.Unlock()
	f.connectorsFileLock.Lock()
	defer f.connectorsFileLock.Unlock()
	f.groupsFileLock.Lock()
	defer f.groupsFileLock.Unlock()
	f.encryptionSessionsFileLock.Lock()
	defer f.encryptionSessionsFileLock.Unlock()

	// release the DB lock
	err := f.databaseLock.Close()
	if err != nil {
		return tracerr.Wrap(err)
	}
	f.databaseLock = nil

	return nil
}

func (f *FileStorage) readCurrentDevice(storage *currentDeviceStorage) error {
	if f.databaseLock == nil {
		return tracerr.Wrap(ErrorDatabaseClosed)
	}
	storage.currentDevice = &currentDevice{}
	f.currentDeviceFileLock.Lock()
	defer f.currentDeviceFileLock.Unlock()
	return readStorage[currentDevice](filepath.Join(f.DatabaseDir, "current_device_storage"), f.EncryptionKey, storage.currentDevice)
}

func (f *FileStorage) writeCurrentDevice(storage *currentDeviceStorage) error {
	if f.databaseLock == nil {
		return tracerr.Wrap(ErrorDatabaseClosed)
	}
	f.currentDeviceFileLock.Lock()
	defer f.currentDeviceFileLock.Unlock()
	return writeStorage[currentDevice](filepath.Join(f.DatabaseDir, "current_device_storage"), f.EncryptionKey, storage.currentDevice)
}

func (f *FileStorage) readContacts(storage *contactsStorage) error {
	if f.databaseLock == nil {
		return tracerr.Wrap(ErrorDatabaseClosed)
	}
	storage.lock.Lock()
	defer storage.lock.Unlock()
	f.contactsFileLock.Lock()
	defer f.contactsFileLock.Unlock()
	storage.contacts = make(map[string]contact)
	return readStorage[map[string]contact](filepath.Join(f.DatabaseDir, "contacts_storage"), f.EncryptionKey, &storage.contacts)
}

func (f *FileStorage) writeContacts(storage *contactsStorage) error {
	if f.databaseLock == nil {
		return tracerr.Wrap(ErrorDatabaseClosed)
	}
	storage.lock.RLock()
	defer storage.lock.RUnlock()
	f.contactsFileLock.Lock()
	defer f.contactsFileLock.Unlock()
	return writeStorage[map[string]contact](filepath.Join(f.DatabaseDir, "contacts_storage"), f.EncryptionKey, &storage.contacts)
}

func (f *FileStorage) readConnectors(storage *connectorsStorage) error {
	if f.databaseLock == nil {
		return tracerr.Wrap(ErrorDatabaseClosed)
	}
	storage.lock.Lock()
	defer storage.lock.Unlock()
	f.connectorsFileLock.Lock()
	defer f.connectorsFileLock.Unlock()
	storage.connectors = make(map[string]common_models.Connector)
	return readStorage[map[string]common_models.Connector](filepath.Join(f.DatabaseDir, "connectors_storage"), f.EncryptionKey, &storage.connectors)
}

func (f *FileStorage) writeConnectors(storage *connectorsStorage) error {
	if f.databaseLock == nil {
		return tracerr.Wrap(ErrorDatabaseClosed)
	}
	storage.lock.RLock()
	defer storage.lock.RUnlock()
	f.connectorsFileLock.Lock()
	defer f.connectorsFileLock.Unlock()
	return writeStorage[map[string]common_models.Connector](filepath.Join(f.DatabaseDir, "connectors_storage"), f.EncryptionKey, &storage.connectors)
}

func (f *FileStorage) readGroups(storage *groupsStorage) error {
	if f.databaseLock == nil {
		return tracerr.Wrap(ErrorDatabaseClosed)
	}
	storage.lock.Lock()
	defer storage.lock.Unlock()
	f.groupsFileLock.Lock()
	defer f.groupsFileLock.Unlock()
	storage.groups = make(map[string]group)
	return readStorage[map[string]group](filepath.Join(f.DatabaseDir, "groups_storage"), f.EncryptionKey, &storage.groups)
}

func (f *FileStorage) writeGroups(storage *groupsStorage) error {
	if f.databaseLock == nil {
		return tracerr.Wrap(ErrorDatabaseClosed)
	}
	storage.lock.RLock()
	defer storage.lock.RUnlock()
	f.groupsFileLock.Lock()
	defer f.groupsFileLock.Unlock()
	return writeStorage[map[string]group](filepath.Join(f.DatabaseDir, "groups_storage"), f.EncryptionKey, &storage.groups)
}

func (f *FileStorage) readEncryptionSessions(storage *encryptionSessionCache) error {
	if f.databaseLock == nil {
		return tracerr.Wrap(ErrorDatabaseClosed)
	}
	storage.lock.Lock()
	defer storage.lock.Unlock()
	f.encryptionSessionsFileLock.Lock()
	defer f.encryptionSessionsFileLock.Unlock()
	storage.encryptionSessions = make(map[string]encryptionSessionCacheEntry)
	return readStorage[map[string]encryptionSessionCacheEntry](filepath.Join(f.DatabaseDir, "encryption_session_storage"), f.EncryptionKey, &storage.encryptionSessions)
}

func (f *FileStorage) writeEncryptionSessions(storage *encryptionSessionCache) error {
	if f.databaseLock == nil {
		return tracerr.Wrap(ErrorDatabaseClosed)
	}
	storage.lock.RLock()
	defer storage.lock.RUnlock()
	f.encryptionSessionsFileLock.Lock()
	defer f.encryptionSessionsFileLock.Unlock()
	return writeStorage[map[string]encryptionSessionCacheEntry](filepath.Join(f.DatabaseDir, "encryption_session_storage"), f.EncryptionKey, &storage.encryptionSessions)
}
