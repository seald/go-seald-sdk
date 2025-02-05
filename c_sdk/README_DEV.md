# C SDK

This file is intended to explain a few concepts of how the C Seald SDK is implemented in GoLang,
and why these choices were made.

## Conventions

Functions exposed to C *must* always take only C-types as arguments, and return a C-type.
These arguments should be casted to Go types when used.

C does not have classes, so to expose a Go struct and its methods to C,
we must pass an "opaque pointer" to C instead (see ["Go Heap"](#go-heap)),
and expose functions which take this "opaque pointer" as first argument.

A function which only returns a simple value can just return it to C.
However, when a function has to also return an error, it should:
- take a pointer to the result type as argument, and write to it in case of success;
- take a `errMsg **C.char` as argument, and write to it in case of error;
- return a `C.int`, with a value of `0` in case of success and `-1` in case of error.

As an example of all these concept, for a method with the signature:

```go
func (instance MyStruct) MyMethod (arg1 int, arg2 string) (string, error)
```

we would expose:

```go
//export MyStruct_MyMethod
func MyStruct_MyMethod(instance *C.MyStruct, arg1 C.int, arg2 *C.char, result **C.char, errMsg **C.char) C.int {
  goArg1 := int(arg1)
  goArg2 := C.GoString(arg2)
  res, err := (*MyStruct)(unsafe.Pointer(instance)).MyMethod(goArg1, goArg2)
  if err != nil {
    *errMsg = C.CString(err.Error())
    return C.int(-1)
  }
  *result = C.CString(res)
  return C.int(0)
}
```

## Memory management

There are 3 types of variables, based on how they are created, that should be handled in different ways.

### Stack

A variable is on the stack when the value (and I do mean the *value* itself, not pointers to it),
is passed as arguments to a function, or returned.

In this case, there is no need to take particular care with it.

### Go Heap

Go manages the memory with garbage-collection.

A variable is on the Go Heap when it is created normally from Go code.

It is *necessary* to do so when we want to instantiate a variable that is an actual Go struct, then pass it to C.

In this case, we cannot expose a Go struct to C, so to pass the variable to C we pass an "opaque pointer" instead:
- In the C header file, we define an empty C struct type (for example `typedef struct MyClass MyClass;`), just to serve as a holder to pointers of this type.
- In Go, we define the real struct type, if necessary.
- In Go, we create a reference map (a `sync.Map` instance, for example `var myClassRefMap = sync.Map{}`). This will avoid instances being garbage-collected when there are no more Go references to them (only C references).
- In Go, we define a helper function to allocate this type (for example `MyClass_New`), which:
    - instantiate the Go struct (for example `instance := &MyClass{}`);
    - stores a pointer to it in the reference map (for example `myClassRefMap.Store(uintptr(unsafe.Pointer(instance)), instance)`);
    - casts the pointer to the actual Go type into a pointer to the corresponding C type and return it (for example `return (*C.MyClass)(unsafe.Pointer(instance))`).
- In Go, we define a helper function to free this type (for example `MyClass_Free`), which removes the pointer from the Go reference map, so Go's garbage-collection can actually free the memory.

We must *always* instantiate this type using the helper function,
never directly from Go code (or it could be garbage-collected when passed to C),
nor directly from C code (or it would actually be a pointer to the empty fake struct, instead of an actual instance of the Go type).

We also must take care of *always* calling the cleaning function when the data is not necessary anymore,
to avoid memory leaks.

Any Go field on the struct will *not* be accessible to C,
so we must take care of defining functions to retrieve any data.

### C Heap

A variable is on the C Heap when it is allocated from C code with `malloc`,
or from Go code with `C.malloc`, `C.CString`, or `C.CBytes`.

In this case, it must be freed from C code (or with `C.free` from Go code).

This can be done from Go code, when we want to return to C some simple data-holding type,
or for types that should be created from C to be passed to Go.

To do this, we define the struct in the C header file, for example:

```c
typedef struct {
    char* FieldString;
    int FieldInt;
} MyStruct;
```

Then, we can instantiate the struct either from C:

```c
MyStruct* instance = (MyStruct*)malloc(sizeof(MyStruct));
if (instance == NULL) {
    /* Handle allocation failure */
}
instance->FieldString = strdup("myString");
if (instance->FieldString == NULL) {
    // Handle allocation failure
}
myStructInstance->FieldInt = 42;
```

Or from Go:

```go
instance := (*C.MyStruct)(C.malloc(C.size_t(unsafe.Sizeof(C.MyStruct{}))))
instance.FieldString = C.CString("myString")
instance.FieldInt = C.int(len(42))
```

When dealing with a struct which contains pointers to other values on the C Heap (for example strings),
it is usual to provide a function to free all the data contained in the struct at once.
This function must call `C.free` (or the appropriate free function) on each sub-value, then on the struct itself:

```go
//export MyStruct_Free
func MyStruct_Free(instance *C.MyStruct) {
	if instance == nil {
		return
	}
	C.free(unsafe.Pointer(instance.FieldString))
	// not necessary to free `FieldInt`, as it is a simple value, not a pointer
	C.free(unsafe.Pointer(instance))
}
```

## Test run 

To build the go lib:
```bash
go build -buildmode=c-shared -buildvcs=false -o build/lib_seald_sdk.so .
```

To build the tests, the following library are needed:
```bash
libjwt-dev libcjson-dev libcurl # dev name might vary if you're not using a good OS.
```

Before running the C tests, you must create a `test_credentials.json` on the root of the repository.
See the root `README.md` for details.

On Linux, the run command is:
```bash
LD_LIBRARY_PATH=./build ./build/test
```

On macOS, you may need to run:
```bash
brew install curl
brew install libjwt
brew install cjson
```

On macOS, the build command will be:
```bash
gcc -o build/test test.c test_ssks_backend.c -L./build -l_seald_sdk -ljwt -lcjson -lcurl -L/opt/homebrew/lib -I/opt/homebrew/include
```

Also, on macOS, the run command is:
```bash
DYLD_LIBRARY_PATH=./build ./build/test
```

## Builds for mobile

### Android

In the `c_sdk` folder:
```bash
export GO386='softfloat' # https://github.com/golang/go/issues/40255
export GOFLAGS=-buildvcs=false
# Make sure `ANDROID_NDK` is defined. For example, in the CI : `export ANDROID_NDK=$ANDROID_HOME/ndk/$NDK_VER`

./build-c-android.sh
```
The build is available in `./build/android-c/jniLibs/`

### iOS

In the `c_sdk` folder, on macOS:
```bash
./build-c-apple.sh
```
The build is available in `./build/apple-c/SealdSdkC.xcframework`

## Lint

Linting uses [`uncrustify`](https://github.com/uncrustify/uncrustify).

Linting rules are defined in `uncrustify.cfg` in the root directory. Configuration is shared.

To install `uncrustify`, use `brew` on macos (`brew install uncrustify`), or your package manager on linux.

To verify formatting, you can run `uncrustify -c ../uncrustify.cfg --check *.c *.h` in the `c_sdk` directory.

To fix formatting, you can run `uncrustify -c ../uncrustify.cfg --no-backup *.c *.h`.
