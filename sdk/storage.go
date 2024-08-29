package sdk

// Database is the interface that must be implemented by the storage backends.
// You should not have to use this directly.
type Database interface { // Must be exported because it is an input type in InitializeOptions
	initialize() error
	close() error
	readCurrentDevice(storage *currentDeviceStorage) error
	writeCurrentDevice(storage *currentDeviceStorage) error
	readContacts(contacts *contactsStorage) error
	writeContacts(contacts *contactsStorage) error
	readGroups(groupDevices *groupsStorage) error
	writeGroups(groupDevices *groupsStorage) error
	readConnectors(contacts *connectorsStorage) error
	writeConnectors(contacts *connectorsStorage) error
	readEncryptionSessions(contacts *encryptionSessionCache) error
	writeEncryptionSessions(contacts *encryptionSessionCache) error
}
