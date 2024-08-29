# Mobile SDK

## Error handling

Looks like the gomobile runtime does NOT like when a `nil` error is from a function which returns something other
than `error` itself, even if it is a compatible interface, and considers it as an actual error.

So, we must **never** do something like `return utils.ToSerializableError(aCallThatCanReturnErrorOrNil())`.
Instead, we must always extend it so the returned `nil` is of the correct type:

```go
err := aCallThatCanReturnErrorOrNil()
if err != nil {
  return utils.ToSerializableError(err)
}
return nil
```
