# Test credentials

To be able to run the tests, you need to have test credentials.
To obtain test credentials, [contact us](mailto:contact@seald.io).

These credentials must be put in a `test_credentials.json` file, in the root of this repository.
You can find a `test_credentials.template.json` that shows the expected format.

# Custom Go toolchain

To build on iOS, in order to avoid random crashes of the SDK (`unaligned arguments` errors), you need to build a custom
Go toolchain, which includes the patch https://go-review.googlesource.com/c/go/+/408395.

To build this custom toolchain, you must:
- Pull the golang project ( https://github.com/golang/go/ ) and checkout the correct version (at the time of writing, the `go1.21.5` tag)
- Modify 2 files:
    - `src/cmd/cgo/out.go` with the same change as in the PR https://go-review.googlesource.com/c/go/+/408395 : adding `__attribute__((aligned(8)))` (warning, the line is not exactly the same as in the PR, it is ~10 lines further)
    - `src/cmd/go/internal/version/version.go` to add `custom-seald-build` on line 81 at the end of the template string (this adds it in the output of `go version`, which is checked in CI to verify that we are using a custom toolchain)
- Go in `src` and run `./all.bash` to build the go toolchain
- Add the path written at the end of the output of the previous command at the beginning of your PATH (warning, for it to be taken into account by the gitlab runner, it must be added to `~/.profile`, not only `~/.zprofile`)

# Release

To publish releases of the SDK to Maven Central (Android), Cocoapods (iOS), and pub.dev (Flutter),
you must push a tag to the repo. The CI will take care of the rest.

The tags **must** be semver valid version numbers.

# Style rules

## Code style

Code must be formatted by `gofmt`.

## File names

File names must be in `snake_case`.

## Gobind limitation
Exposed functions must return either no results, one result, or two results where the type of the second is the built-in 'error' type.

When an exposed function returns a custom type, this type can only be a struct. https://github.com/golang/go/issues/27297


Package names cannot collide with struct names. macOS will have troubles with case-insensitive path...

## Logs
The `State` has its own zerolog logger instance in `state.Logger`. Each API has a dedicated sub-logger.

Available log levels:
- panic
- fatal
- error
- warn
- info
- debug
- trace

To log a message:
Get the instance logger, choose a log level, and use the `Msg()` function:
`logger.Debug().Msg("My debug log")`

To add contextual fields to a log message:
- Add a string: `logger.Trace().Str("str to log", strToLog).Msg("Trace level log message")`
- Add a struct `logger.Info().Interface("struc name", myStruct).Msg("Info level log message")`

## Errors

### Passing errors

When a function you call returns an error, and you want to pass it along,
you must use `tracerr.Wrap`:

```go
package myPackage

import "github.com/ztrue/tracerr"

func myFunc() (*ReturnType, error) {
	err := FunctionWhichCanReturnError()
	if err != nil {
		return nil, tracerr.Wrap(err)
	}
	// ...
}
```

### Creating errors

When you need to create a new error, you must not create it inside your function code.
Instead, you must create it in global scope, with `utils.NewSealdError` and a **unique** error message,
and store it in an exported `var`, so that anyone using the function can compare the error they receive to it.

When there are multiple errors in the same file, they must all be in a single `var` declaration,
with parenthesis.

Additionally, your error must have a very specific unique name and error message,
potentially with the function name which can return it inside.

When you need to return the error in question, you must use `tracerr.Wrap`.
You can either wrap the error directly, or use `.AddDetails("details to add")` to add details to the error.

Also, do not forget the errors' [GoDoc](#godoc).

```go
package myPackage

import (
	"github.com/ztrue/tracerr"
	"github.com/seald/go-seald-sdk/utils"
)

var (
	// ErrorName is returned when condition1
	ErrorName = utils.NewSealdError("unique error message")
	// ErrorMyFuncErrorType is returned when condition2
	ErrorMyFuncErrorType = utils.NewSealdError("other unique error message")
)

func myFunc() (*ReturnType, error) {
	if condition1 {
		return nil, tracerr.Wrap(ErrorName)
	}
	if condition2 {
		return nil, tracerr.Wrap(ErrorMyFuncErrorType.AddDetails("my details to add"))
	}
	// ...
	return nil, nil
}
```

### Comparing errors

For comparing errors, you should use `errors.Is`.

For SealdErrors, you should compare them to the exported error in question.

```go
package myPackage

import (
	"errors"
	"github.com/ztrue/tracerr"
	"github.com/seald/go-seald-sdk/utils"
)

func otherFunc() error {
	_, err = myFunc()
	if err != nil {
		if errors.Is(err, ErrorMyFuncErrorType) {
			// Do something specific
        }
		return err
	}
	return nil
}
```

For API Errors, you should compare them to a newly created `APIError` instance, with Status and Code set.

```go
package myPackage

import (
	"errors"
	"github.com/ztrue/tracerr"
	"github.com/seald/go-seald-sdk/utils"
)

func otherFunc() error {
	_, err = apiStuff()
	if err != nil {
		if errors.Is(err, utils.APIError{Status: 406, Code: "MY_ERROR_CODE"}) {
			// Do something specific
		}
		return err
	}
	return nil
}
```

You may also want to cast the retrieved error as a specific type (either `utils.SealdError` or `utils.APIError`),
with `errors.As`.
You should rarely have to do this. You probably want to use `errors.Is` instead.

```go
package myPackage

import (
	"errors"
	"github.com/ztrue/tracerr"
	"github.com/seald/go-seald-sdk/utils"
)

func otherFunc() error {
	_, err = apiStuff()
	if err != nil {
		var apiError utils.APIError
		if errors.As(err, &apiError) { // casting the error as an `APIError`
			// you can then use `apiError` as an instance of a`APIError`
		} else {
			// `err` is not an `APIError`
        }
		return err
	}
	return nil
}
```

## GoDoc

Every exported symbol must have GoDoc comments.
Official guidelines: [https://go.dev/doc/comment](https://go.dev/doc/comment).

The GoDoc comment must start with `//`, followed by a space.
It must be a complete sentence, starting with a capital letter and ending with a point.
All doc comments must start by explicitly stating the name of the symbol they are documenting,
possibly prefixed by an article.

In doc comments, you can refer to argument names, or other exported symbols,
directly by name, without back quotes or any special syntax.
You may also want to name the return types to refer to them.

Example:

```go
package myPackage

import (
	"errors"
)

var (
	// ErrorName is returned when there is an error in MyFunc.
	ErrorName = errors.New("error message")
)

// MyReturnType is the type that MyFunc returns.
type MyReturnType struct {
	// You can also document type fields, but that is not mandatory,
	// as long as the field meaning is sufficiently self-explanatory,
	// or explained in the type's doc comment.
	MyField string
}

// The MyFunc function does stuff. It takes myArg, and will return myReturnInstance, a pointer to MyReturnType, or myError.
func MyFunc(myArg string) (myReturnInstance *MyReturnType, myError error) {
	v := MyReturnType{MyField: myArg}
	return &v, nil
}
```

## Tests

When implementing new features in GoLang, they should be tested, both against the GoLang SDK itself,
and if applicable against the JS SDK

### GoLang tests

When implementing tests in GoLang, you should test both the normal cases, and the error cases, as much as possible.
You should strive for 100% coverage if possible. The only lines which are acceptable to not tests are those that simply
test for an error and re-throw it, if the error in question is otherwise tested.

In tests, you should use `require.NoError(t, err)` to check for errors, instead of an `if` block,
for the sake of readability and consistency.

Also, you should use `t.Parallel()` everywhere possible, to reduce the duration of tests.

### Tests against JS

To test the GoLang implementation against the JS SDK,
you may need to execute JS code both before and after your GoLang tests.
A common pattern is to create artifacts in JS,
then use them in Go to verify than the Go implementation is compatible with them,
then create other artifacts in Go, and use them in JS to verify the other way around.

To do so, for example for a module named `my_module`,
you should create a mocha JS test file in `tests_js/before_go/my_module.spec.js`,
which creates the necessary artifacts in `test_artifacts/from_js/my_module/`.
Artifacts must be named in `snake_case`.

After that, you can implement the necessary tests in GoLang in your `my_module_test.go` file.
This file should both test the artifacts generated by the JS, and generate new artifacts from GoLang for the JS to test.
These new artifacts must be in `test_artifacts/from_go/my_module/`, and follow the same rules as previously.

You may want to use the following pattern:

```go
package my_module

import (
	"github.com/stretchr/testify/require"
	"github.com/seald/go-seald-sdk/test_utils"
	"os"
	"path/filepath"
	"testing"
)

func Test_MyModule(t *testing.T) {
	t.Parallel()
	// Other tests ...
	t.Run("Compatible with JS", func(t *testing.T) {
		t.Parallel()
		t.Run("Import from JS", func(t *testing.T) {
			testArtifactsDir := filepath.Join(test_utils.GetCurrentPath(), "../test_artifacts/from_js/my_module")

			// Reading an artifact
			myArtifact, err := os.ReadFile(filepath.Join(testArtifactsDir, "my_artifact"))
			require.NoError(t, err)

			// implement Go tests for the JS artifacts
			err = TestArtifact(myArtifact)
			require.NoError(t, err)
		})
		t.Run("Export for JS", func(t *testing.T) {
			// ensure artifacts dir exists
			testArtifactsDir := filepath.Join(test_utils.GetCurrentPath(), "../test_artifacts/from_go/my_module")
			err := os.MkdirAll(testArtifactsDir, 0700)
			require.NoError(t, err)

			// implement Go tests to write artifacts
			myArtifact := GenerateArtifactSomehow()
			err = os.WriteFile(filepath.Join(testArtifactsDir, "my_artifact"), myArtifact, 0o700)
		})
	})
}
```

Lastly, you must create a mocha JS test file in `tests_js/after_go/my_module.spec.js` file,
which reads the artifacts created by the GoLang test and tests them against the JS SDK.

In general, the JS test in `before_go` will follow the same logic as the GoLang test in `Export for JS`,
and the JS test in `after_go` will follow the GoLang test in `Import from JS`.
Also, the JS and GoLang should generate the same artifacts.
