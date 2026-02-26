package regexp

import (
	"regexp"
	"runtime"
	"sync"
	"weak"
)

// Interns the compilation of Regular Expressions.  If two regexs with the same pattern are compiled, the result
// is the same *regexp.Regexp.  This avoids the compilation cost but more importantly the memory usage.
//
// Regular expressions produced from this package are backed by a form of weak-valued map, upon a regexp becoming
// unreachable, they will be eventually removed from the map and memory reclaimed.

var (
	weakMap      = make(map[string]weak.Pointer[regexp.Regexp])
	posixWeakMap = make(map[string]weak.Pointer[regexp.Regexp])
	reverseMap   = make(map[weak.Pointer[regexp.Regexp]]string)
	l            sync.Mutex
)

// CompileInterned compiles and interns a regular expression and returns a
// pointer to it or an error.
func CompileInterned(pattern string) (*regexp.Regexp, error) {
	return compile(pattern, regexp.Compile, weakMap)
}

// CompilePOSIXInterned compiles and interns a regular expression using POSIX
// syntax and returns a pointer to it or an error.
func CompilePOSIXInterned(pattern string) (*regexp.Regexp, error) {
	return compile(pattern, regexp.CompilePOSIX, posixWeakMap)
}

// MustCompileInterned compiles and interns a regular expression and returns a pointer to it or panics.
func MustCompileInterned(pattern string) *regexp.Regexp {
	return mustCompile(pattern, regexp.MustCompile, weakMap)
}

// MustCompilePOSIXInterned compiles and interns a regular expression using
// POSIX syntax and returns a pointer to it or panics.
func MustCompilePOSIXInterned(pattern string) *regexp.Regexp {
	return mustCompile(pattern, regexp.MustCompilePOSIX, posixWeakMap)
}

// compile handles compiling and interning regular expressions. If the regexp is
// already interned, a pointer to it is returned from the map. If the regexp is
// not interned or is nil (since it's a weak pointer), it is compiled and stored
// in the maps. The regexp is stored in the maps as a weak pointer, so that it
// can be garbage collected.
func compile(pattern string, compileFunc func(string) (*regexp.Regexp, error), internedPointers map[string]weak.Pointer[regexp.Regexp]) (*regexp.Regexp, error) {
	l.Lock()
	defer l.Unlock()
	if itemPtr, ok := internedPointers[pattern]; ok {
		ptr := itemPtr.Value()
		if ptr != nil {
			return ptr, nil
		}
		delete(internedPointers, pattern)
		delete(reverseMap, itemPtr)
	}
	r, err := compileFunc(pattern)
	if err != nil {
		return nil, err
	}
	weakPointer := weak.Make(r)
	internedPointers[pattern] = weakPointer
	reverseMap[weakPointer] = pattern

	// Register a cleanup function for the regexp object
	cleanup := func(ptr weak.Pointer[regexp.Regexp]) {
		cleanupCollectedPointers(ptr, internedPointers)
	}
	runtime.AddCleanup(r, cleanup, weakPointer)

	return r, nil
}

// mustCompile is a wrapper around compile that is used when we want to panic
// instead of returning an error. If the regexp is already interned, a pointer
// to it is returned from the map. If the regexp is not interned or is nil
// (since it's a weak pointer), it is compiled and stored in the maps. The
// regexp is stored in the maps as a weak pointer, so that it can be garbage
// collected.
func mustCompile(pattern string, mustCompileFunc func(string) *regexp.Regexp, internedPointers map[string]weak.Pointer[regexp.Regexp]) *regexp.Regexp {
	compileFunc := func(string) (*regexp.Regexp, error) {
		return mustCompileFunc(pattern), nil
	}
	res, _ := compile(pattern, compileFunc, internedPointers)
	return res
}

// cleanupCollectedPointers is a cleanup function for *regexp.Regexp. It removes
// the entries from relevant maps when the regexp object they point to is
// garbage collected.
func cleanupCollectedPointers(ptr weak.Pointer[regexp.Regexp], internedPointers map[string]weak.Pointer[regexp.Regexp]) {
	l.Lock()
	defer l.Unlock()
	if s, ok := reverseMap[ptr]; ok {
		delete(internedPointers, s)
		delete(reverseMap, ptr)
	}
}
