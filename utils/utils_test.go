package utils

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

const UUID_EXAMPLE = "00000000-0000-1000-a000-7ea300000000"
const B64_UUID_EXAMPLE = "AAAAAAAAEACgAH6jAAAAAA"

const license_test_vector_nonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const license_test_vector_user_id = "test-userid-for-license"
const license_test_vector_app_id = "00000000-0000-1000-a000-7ea300000000"
const license_test_vector_validation_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
const license_test_vector_validation_key_id = "00000000-0000-1000-a000-d11c1d000000"
const license_test_vector_token = "00000000-0000-1000-a000-d11c1d000000:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:fde8bc5ce7a42021062a9b4c2412c2f32cb0c058309d6be8ab67672a3ef9c45cadbb0f4babda52abf294b2de69e04ada1780a1473d3dd7516eaac33087a797e1"

func TestB64toS64(t *testing.T) {
	for i := 0; i < 1000; i++ {
		data, err := GenerateRandomBytes(i)
		if err != nil {
			t.Log("error should be nil", err)
			t.Fail()
			return
		}
		b64Data := base64.StdEncoding.EncodeToString(data)
		s64Data := B64toS64(b64Data)
		b64Data2 := S64toB64(s64Data)
		if b64Data != b64Data2 {
			t.Log("Should be equal")
			t.Fail()
			return
		}
	}
}

func TestUUID(t *testing.T) {
	// B64UUID good UUID
	b64uuid, err := B64UUID(UUID_EXAMPLE)
	if err != nil {
		t.Log("error should be nil", err)
		t.Fail()
		return
	}
	if b64uuid != B64_UUID_EXAMPLE {
		t.Log("Should be equal")
		t.Fail()
		return
	}

	// UnB64UUID good UUID
	uuid, err := UnB64UUID(B64_UUID_EXAMPLE)
	if err != nil {
		t.Log("error should be nil", err)
		t.Fail()
		return
	}
	if uuid != UUID_EXAMPLE {
		t.Log("Should be equal")
		t.Fail()
		return
	}

	// B64UUID bad UUID
	_, err = B64UUID("BAD_UUID")
	if err == nil {
		t.Log("error should NOT be nil", err)
		t.Fail()
		return
	}

	// UnB64UUID bad UUID
	_, err = UnB64UUID("BAD_UUID")
	if err == nil {
		t.Log("error should NOT be nil", err)
		t.Fail()
		return
	}
}

func TestGenerateUserLicenseToken(t *testing.T) {
	token, err := GenerateUserLicenseToken(license_test_vector_nonce, license_test_vector_user_id, license_test_vector_app_id, license_test_vector_validation_key, license_test_vector_validation_key_id)
	if err != nil {
		t.Log("error should be nil", err)
		t.Fail()
		return
	}
	if token != license_test_vector_token {
		t.Log("Generated token is different from expected:", token)
		t.Fail()
		return
	}
}

func TestSliceSameMembers(t *testing.T) {
	// empty case
	assert.True(t, SliceSameMembers([]int{}, []int{}))
	// empty vs nil
	assert.True(t, SliceSameMembers([]int{}, nil))
	// nil vs empty
	assert.True(t, SliceSameMembers(nil, []int{}))
	// nil vs nil with explicit typing
	assert.True(t, SliceSameMembers[int](nil, nil))
	// simple true case
	assert.True(t, SliceSameMembers([]int{1, 2, 3}, []int{1, 2, 3}))
	// true case with different order
	assert.True(t, SliceSameMembers([]int{1, 2, 3}, []int{3, 2, 1}))
	// true case with duplicates
	assert.True(t, SliceSameMembers([]int{1, 2, 2, 3, 3}, []int{1, 2, 2, 3, 3}))
	// true case with duplicates and different order
	assert.True(t, SliceSameMembers([]int{1, 2, 2, 3, 3}, []int{1, 2, 3, 2, 3}))
	// simple true case with strings
	assert.True(t, SliceSameMembers([]string{"a", "b", "c"}, []string{"a", "b", "c"}))
	// different length false case
	assert.False(t, SliceSameMembers([]int{1, 2, 3}, []int{4, 5}))
	// simple false case
	assert.False(t, SliceSameMembers([]int{1, 2, 3}, []int{4, 5, 6}))
	// same members but not same number of each instance
	assert.False(t, SliceSameMembers([]int{1, 2, 2, 3}, []int{1, 2, 3, 3}))
	// slice vs empty
	assert.False(t, SliceSameMembers([]int{1, 2, 3}, []int{}))
	// slice vs nil
	assert.False(t, SliceSameMembers([]int{1, 2, 3}, nil))
}

func TestSliceMap(t *testing.T) {
	assert.Equal(t,
		[]int{2, 3, 4},
		SliceMap([]int{1, 2, 3}, func(e int) int { return e + 1 }),
	)
}

func TestSliceIncludes(t *testing.T) {
	assert.True(t, SliceIncludes([]int{1, 2, 3}, 1))
	assert.True(t, SliceIncludes([]int{1, 2, 3}, 2))
	assert.True(t, SliceIncludes([]int{1, 2, 3}, 3))
	assert.False(t, SliceIncludes([]int{1, 2, 3}, 4))
	assert.False(t, SliceIncludes([]int{1, 2, 3}, 0))
}

func TestChunkSlice(t *testing.T) {
	evenArrayToSlice := []int{0, 1, 2, 3}

	evenChunks := ChunkSlice[int](evenArrayToSlice, 2)
	assert.Equal(t, []int{0, 1}, evenChunks[0])
	assert.Equal(t, []int{2, 3}, evenChunks[1])

	oddArrayToSlice := []int{0, 1, 2, 3, 4}

	oddChunks := ChunkSlice[int](oddArrayToSlice, 2)
	assert.Equal(t, []int{0, 1}, oddChunks[0])
	assert.Equal(t, []int{2, 3}, oddChunks[1])
	assert.Equal(t, []int{4}, oddChunks[2])
}

func TestUniqueSlice(t *testing.T) {
	notUniqueArray := []int{0, 1, 1, 2, 3}

	assert.True(t, SliceSameMembers(
		[]int{0, 1, 2, 3},
		UniqueSlice[int](notUniqueArray),
	))
}

func TestCheckSliceUnique(t *testing.T) {
	assert.Nil(t, CheckSliceUnique([]int{0, 1, 2, 3}))
	assert.ErrorIs(t, CheckSliceUnique([]int{0, 1, 1, 2, 3}), ErrorNotUnique)
}

func TestSet(t *testing.T) {
	s := Set[int]{}
	assert.Equal(t, len(s), 0)
	assert.False(t, s.Has(10))
	s.Add(10)
	assert.Equal(t, len(s), 1)
	assert.False(t, s.Has(20))
	assert.True(t, s.Has(10))
	s.Add(10)
	assert.Equal(t, len(s), 1)
	assert.True(t, s.Has(10))
	s.Remove(0) // asserts this is no-op
	assert.Equal(t, len(s), 1)
	s.Remove(10)
	assert.False(t, s.Has(10))
	assert.Equal(t, len(s), 0)

	s2 := Set[unsafe.Pointer]{} // a pointer is comparable, see https://go.dev/ref/spec#Comparison_operators
	assert.Equal(t, len(s2), 0)
	assert.False(t, s2.Has(nil))
	s2.Add(nil)
	assert.Equal(t, len(s2), 1)
	assert.True(t, s2.Has(nil))
	el := struct{}{}
	assert.False(t, s2.Has(unsafe.Pointer(&el)))
	s2.Add(unsafe.Pointer(&el))
	assert.True(t, s2.Has(unsafe.Pointer(&el)))
	assert.Equal(t, len(s2), 2)
	s2.Remove(nil)
	assert.False(t, s2.Has(nil))
	assert.Equal(t, len(s2), 1)
	s2.Remove(nil)
	assert.False(t, s2.Has(nil))
	assert.Equal(t, len(s2), 1)
}

func TestMutexGroup(t *testing.T) {
	t.Parallel()
	t.Run("cannot acquire the same lock a second time, until unlock", func(t *testing.T) {
		group := MutexGroup{}
		group.Lock("lock")
		lockAcquired := false
		go func() {
			group.Lock("lock")
			lockAcquired = true
		}()
		time.Sleep(1 * time.Millisecond)
		require.Equal(t, false, lockAcquired)
		group.Unlock("lock")
		time.Sleep(1 * time.Millisecond)
		require.Equal(t, true, lockAcquired)
		group.Unlock("lock")
	})
	t.Run("can acquire a different lock", func(t *testing.T) {
		group := MutexGroup{}
		group.Lock("lock-1")
		lockAcquired := false
		go func() {
			group.Lock("lock-2")
			lockAcquired = true
		}()
		time.Sleep(1 * time.Millisecond)
		require.Equal(t, true, lockAcquired)
		group.Unlock("lock-1")
		group.Unlock("lock-2")
	})
	t.Run("cannot acquire the global lock a second time, until unlock", func(t *testing.T) {
		group := MutexGroup{}
		group.LockAll()
		lockAcquired := false
		go func() {
			group.LockAll()
			lockAcquired = true
		}()
		time.Sleep(1 * time.Millisecond)
		require.Equal(t, false, lockAcquired)
		group.UnlockAll()
		time.Sleep(1 * time.Millisecond)
		require.Equal(t, true, lockAcquired)
		group.UnlockAll()
	})
	t.Run("cannot acquire a global lock while there is a local lock", func(t *testing.T) {
		group := MutexGroup{}
		group.Lock("lock")
		lockAcquired := false
		go func() {
			group.LockAll()
			lockAcquired = true
		}()
		time.Sleep(1 * time.Millisecond)
		require.Equal(t, false, lockAcquired)
		group.Unlock("lock")
		time.Sleep(1 * time.Millisecond)
		require.Equal(t, true, lockAcquired)
		group.UnlockAll()
	})
	t.Run("cannot release a local lock that was never acquired", func(t *testing.T) {
		group := MutexGroup{}
		assert.Panics(t, func() {
			group.Unlock("lock")
		})
	})
	t.Run("cannot release a local lock that exists but isn't locked", func(t *testing.T) {
		t.Skip("Bad unlock causes unrecoverable panic")
		group := MutexGroup{}
		group.Lock("lock")
		group.Unlock("lock")
		assert.Panics(t, func() {
			group.Unlock("lock")
		})
	})
	t.Run("cannot release the global lock that wasn't acquired", func(t *testing.T) {
		t.Skip("Bad unlock causes unrecoverable panic")
		group := MutexGroup{}
		assert.Panics(t, func() {
			group.UnlockAll()
		})
	})
	t.Run("can LockMultiple / UnlockMultiple", func(t *testing.T) {
		group := MutexGroup{}
		group.LockMultiple([]string{"lock1", "lock2"})
		lockAcquired := false
		go func() {
			group.Lock("lock1")
			lockAcquired = true
		}()
		time.Sleep(1 * time.Millisecond)
		require.Equal(t, false, lockAcquired)
		group.UnlockMultiple([]string{"lock1", "lock2"})
		time.Sleep(1 * time.Millisecond)
		require.Equal(t, true, lockAcquired)
		group.Unlock("lock1")
	})
	t.Run("no deadlock on LockMultiple", func(t *testing.T) {
		group := MutexGroup{}
		var acquired atomic.Int32
		go func() {
			group.LockMultiple([]string{"lock1", "lock2"})
			acquired.Add(1)
		}()
		go func() {
			group.LockMultiple([]string{"lock2", "lock1"})
			acquired.Add(1)
		}()
		time.Sleep(1 * time.Millisecond)
		require.Equal(t, int32(1), acquired.Load())
		group.UnlockMultiple([]string{"lock2", "lock1"})
		time.Sleep(1 * time.Millisecond)
		require.Equal(t, int32(2), acquired.Load())
		group.UnlockMultiple([]string{"lock1", "lock2"})
	})
}

func TestBase64DecodeString(t *testing.T) {
	decodedRaw, err := Base64DecodeString("SGVsbG8gd29ybGQ")
	require.NoError(t, err)
	assert.Equal(t, []byte("Hello world"), decodedRaw)
	decodedPadded, err := Base64DecodeString("SGVsbG8gd29ybGQ=")
	require.NoError(t, err)
	assert.Equal(t, []byte("Hello world"), decodedPadded)
	decodedPaddedNewlines, err := Base64DecodeString("\nSGVsbG8g\nd29ybGQ=\n")
	require.NoError(t, err)
	assert.Equal(t, []byte("Hello world"), decodedPaddedNewlines)
	decodedRawNewlines, err := Base64DecodeString("\nSGVsbG8g\nd29ybGQ\n")
	require.NoError(t, err)
	assert.Equal(t, []byte("Hello world"), decodedRawNewlines)
}
