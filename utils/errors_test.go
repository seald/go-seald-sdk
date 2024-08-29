package utils

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestErrors(t *testing.T) {
	t.Run("SealdError", func(t *testing.T) {
		// Create errors
		SealdError1 := NewSealdError("TEST_ERROR_1", "SealdError1")
		SealdError2 := NewSealdError("TEST_ERROR_2", "SealdError2")

		// Instantiate errors
		sealdError1a := SealdError1.AddDetails("a")
		sealdError1b := SealdError1.AddDetails("b")
		sealdError2a := SealdError2.AddDetails("a")

		assert.ErrorIs(t, sealdError1a, SealdError1)  // proper use of Is
		assert.ErrorIs(t, sealdError1a, sealdError1b) // weird use of Is
		assert.NotErrorIs(t, sealdError1a, SealdError2)
		assert.NotErrorIs(t, sealdError1a, sealdError2a)

		assert.Equal(t, "TEST_ERROR_1 - SealdError1 : a", sealdError1a.Error())
		assert.Equal(t, "TEST_ERROR_1 - SealdError1", SealdError1.Error())

		assert.NotErrorIs(t, sealdError1a, errors.New("SealdError1"))

		_ = NewSealdError("TEST_DUPLICATE_ERROR", "duplicate error")
		assert.Panics(t, func() {
			_ = NewSealdError("TEST_DUPLICATE_ERROR", "duplicate error")
		})
	})
	t.Run("APIError", func(t *testing.T) {
		apiError404 := APIError{Status: 404, Code: "CODE404", Id: "ID404", Details: "details"}
		apiError500 := APIError{Status: 500, Code: "CODE500", Id: "ID500", Details: "details"}
		apiErrorOther404 := APIError{Status: 404, Code: "CODE404"}
		apiErrorDifferent404 := APIError{Status: 404, Code: "CODE404_2", Id: "ID404_2", Details: "details"}

		assert.ErrorIs(t, apiError404, apiErrorOther404)
		assert.NotErrorIs(t, apiErrorDifferent404, apiErrorOther404)
		assert.NotErrorIs(t, apiError404, apiError500)

		assert.Equal(t, "API Error: status: 404; code: CODE404; id: ID404; details: details", apiError404.Error())
		assert.Equal(t, "API Error: status: 404; code: CODE404", apiErrorOther404.Error())

		assert.NotErrorIs(t, apiError404, errors.New("CODE404"))
	})
}
