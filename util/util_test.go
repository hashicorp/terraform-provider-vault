package util

import (
	"fmt"
	"reflect"
	"testing"
)

type testingStruct struct {
	foobar bool
	list   []string
}

func TestExpiredTokenError(t *testing.T) {
	if ok := IsExpiredTokenErr(fmt.Errorf("error: invalid accessor custom_accesor_value")); !ok {
		t.Errorf("Should be expired")
	}
	if ok := IsExpiredTokenErr(fmt.Errorf("error: failed to find accessor entry custom_accesor_value")); !ok {
		t.Errorf("Should be expired")
	}
	if ok := IsExpiredTokenErr(nil); ok {
		t.Errorf("Shouldn't be expired")
	}
	if ok := IsExpiredTokenErr(fmt.Errorf("Error making request")); ok {
		t.Errorf("Shouldn't be expired")
	}
}

func TestSliceHasElement_scalar(t *testing.T) {
	slice := []interface{}{1, 2, 3, 4, 5}

	found, index := SliceHasElement(slice, 2)
	if !found && index != 1 {
		t.Errorf("Slice should find element")
	}

	found, index = SliceHasElement(slice, 10)
	if found && index != -1 {
		t.Errorf("Slice should not find element")
	}
}

func TestSliceHasElement_struct(t *testing.T) {
	slice := []interface{}{
		testingStruct{foobar: false, list: []string{"hello", "world"}},
		testingStruct{foobar: true, list: []string{"best", "line", "on", "the", "citadel"}},
		testingStruct{foobar: true, list: []string{"I", "gotta", "go"}},
	}

	found, index := SliceHasElement(slice, testingStruct{foobar: true, list: []string{"I", "gotta", "go"}})
	if !found && index != 1 {
		t.Errorf("Slice should find element")
	}

	found, index = SliceHasElement(slice, testingStruct{foobar: false, list: []string{}})
	if found && index != -1 {
		t.Errorf("Slice should not find element")
	}

	found, index = SliceHasElement(slice, 10)
	if found && index != -1 {
		t.Errorf("Slice should not find element")
	}
}

func TestSliceAppendIfMissing_scalar(t *testing.T) {
	slice := []interface{}{1, 2, 3, 4, 5}
	expectedAppend := []interface{}{1, 2, 3, 4, 5, 6}

	append := SliceAppendIfMissing(slice, 3)
	if !reflect.DeepEqual(slice, append) {
		t.Errorf("Slice should not be appended")
	}

	append = SliceAppendIfMissing(slice, 6)
	if !reflect.DeepEqual(expectedAppend, append) {
		t.Errorf("Slice should be appended")
	}
}

func TestSliceAppendIfMissing_struct(t *testing.T) {
	slice := []interface{}{
		testingStruct{foobar: false, list: []string{"hello", "world"}},
		testingStruct{foobar: true, list: []string{"best", "line", "on", "the", "citadel"}},
	}
	expectedAppend := []interface{}{
		testingStruct{foobar: false, list: []string{"hello", "world"}},
		testingStruct{foobar: true, list: []string{"best", "line", "on", "the", "citadel"}},
		testingStruct{foobar: true, list: []string{"I", "gotta", "go"}},
	}

	append := SliceAppendIfMissing(slice, testingStruct{foobar: false, list: []string{"hello", "world"}})
	if !reflect.DeepEqual(slice, append) {
		t.Errorf("Slice should not be appended")
	}

	append = SliceAppendIfMissing(slice, testingStruct{foobar: true, list: []string{"I", "gotta", "go"}})
	if !reflect.DeepEqual(expectedAppend, append) {
		t.Errorf("Slice should be appended")
	}
}

func TestSliceRemoveIfPresent_scalar(t *testing.T) {
	slice := []interface{}{1, 2, 3, 4, 5}
	expected := []interface{}{1, 2, 5, 4}

	removed := SliceRemoveIfPresent(slice, 10)
	if !reflect.DeepEqual(slice, removed) {
		t.Errorf("Slice should not be modified")
	}

	removed = SliceRemoveIfPresent(slice, 3)
	if !reflect.DeepEqual(expected, removed) {
		t.Errorf("Slice should be modified")
	}

	empty := make([]interface{}, 0)
	if len(SliceRemoveIfPresent(empty, 0)) != 0 {
		t.Errorf("Slice should be empty")
	}

	single := []interface{}{1}
	if len(SliceRemoveIfPresent(single, 1)) != 0 {
		t.Errorf("Slice should be empty")
	}
}

func TestSliceRemoveIfPresent_struct(t *testing.T) {
	slice := []interface{}{
		testingStruct{foobar: false, list: []string{"hello", "world"}},
		testingStruct{foobar: true, list: []string{"best", "line", "on", "the", "citadel"}},
		testingStruct{foobar: true, list: []string{"I", "gotta", "go"}},
	}
	expected := []interface{}{
		testingStruct{foobar: true, list: []string{"I", "gotta", "go"}},
		testingStruct{foobar: true, list: []string{"best", "line", "on", "the", "citadel"}},
	}

	removed := SliceRemoveIfPresent(slice, testingStruct{foobar: false, list: []string{}})
	if !reflect.DeepEqual(slice, removed) {
		t.Errorf("Slice should not be modified")
	}

	removed = SliceRemoveIfPresent(slice, testingStruct{foobar: false, list: []string{"hello", "world"}})
	if !reflect.DeepEqual(expected, removed) {
		t.Errorf("Slice should be modified")
	}
}
