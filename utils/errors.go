package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ztrue/tracerr"
)

type SealdError struct {
	Code        string
	Description string
	Details     string
}

var knownErrors = Set[string]{}

func NewSealdError(code string, description string) SealdError {
	if knownErrors.Has(code) {
		panic("Duplicate error: " + code)
	}
	knownErrors.Add(code)
	return SealdError{
		Code:        code,
		Description: description,
	}
}

func (err SealdError) Error() string {
	var text = err.Code
	if err.Description != "" {
		text = text + " - " + err.Description
	}
	if err.Details != "" {
		text = text + " : " + err.Details
	}
	return text
}

func (err SealdError) Is(target error) bool {
	var sealdErrorTarget SealdError
	if errors.As(target, &sealdErrorTarget) {
		return sealdErrorTarget.Code == err.Code
	} else {
		return false
	}
}

func (err SealdError) AddDetails(details string) SealdError {
	if err.Details != "" {
		panic("Cannot re-add details to an error")
	}
	newErr := err
	newErr.Details = details
	return newErr
}

type APIError struct {
	Status  int
	Url     string
	Method  string
	Code    string
	Id      string
	Details string
	Raw     string
}

func (err APIError) Error() string {
	s := fmt.Sprintf("API Error: status: %d", err.Status)
	if err.Code != "" {
		s += "; code: " + err.Code
	}
	if err.Id != "" {
		s += "; id: " + err.Id
	}
	if err.Details != "" {
		s += "; details: " + err.Details
	}
	if err.Url != "" {
		s += "; URL: " + err.Url
	}
	if err.Method != "" {
		s += "; Method: " + err.Method
	}
	if err.Raw != "" {
		s += "; raw: " + err.Raw
	}
	return s
}

func (err APIError) Is(target error) bool {
	var apiErrorTarget APIError
	if errors.As(target, &apiErrorTarget) {
		return apiErrorTarget.Status == err.Status && apiErrorTarget.Code == err.Code
	} else {
		return false
	}
}

type SerializableError struct {
	Status      int    `json:"status"`
	Code        string `json:"code"`
	Id          string `json:"id"`
	Description string `json:"description"`
	Details     string `json:"details"`
	Raw         string `json:"raw"`
	Stack       string `json:"stack"`
}

func (e SerializableError) Error() string {
	res, err := json.Marshal(e)
	if err != nil {
		return fmt.Sprintf("{\"code\": \"SERIALIZATION_ERROR\": \"details\": \"%s\"}", err)
	}
	return string(res)
}

func ToSerializableError(err error) *SerializableError {
	if err == nil {
		return nil
	}
	var apiError APIError
	if errors.As(err, &apiError) {
		return &SerializableError{
			Status:  apiError.Status,
			Code:    apiError.Code,
			Id:      apiError.Id,
			Details: fmt.Sprintf("%s; %s on %s", apiError.Details, apiError.Method, apiError.Url), // Lazy solution. We just want the URL to be shown.
			Raw:     apiError.Raw,
			Stack:   tracerr.Sprint(err),
		}
	}
	var sealdError SealdError
	if errors.As(err, &sealdError) {
		return &SerializableError{
			Code:        sealdError.Code,
			Id:          "GOSDK_" + sealdError.Code,
			Description: sealdError.Description,
			Details:     sealdError.Details,
			Stack:       tracerr.Sprint(err),
		}
	}
	return &SerializableError{
		Code:    "OTHER_ERROR",
		Id:      "GOSDK_OTHER_ERROR",
		Details: err.Error(),
		Stack:   tracerr.Sprint(err),
	}
}
