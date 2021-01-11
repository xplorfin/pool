package pool

// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Heavily inspired by https://github.com/btcsuite/btcd/blob/master/version.go
// Copyright (C) 2015-2019 The Lightning Network Developers

import (
	"fmt"
)

// Commit stores the current commit hash of this build, this should be set
// using the -ldflags during compilation.
var Commit string

// semanticAlphabet
const semanticAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"

// These constants define the application version and follow the semantic
// versioning 2.0.0 spec (http://semver.org/).
const (
	appMajor uint = 0
	appMinor uint = 4
	appPatch uint = 1

	// appPreRelease MUST only contain characters from semanticAlphabet per
	// the semantic versioning spec.
	appPreRelease        = "alpha"
	appPrereleaseVersion = 1
)

// Version returns the application version as a properly formed string per the
// semantic versioning 2.0.0 spec (http://semver.org/).
func Version() string {
	// Start with the major, minor, and patch versions.
	version := fmt.Sprintf("%d.%d.%d", appMajor, appMinor, appPatch)

	// Append pre-release version if there is one.  The hyphen called for
	// by the semantic versioning spec is automatically appended and should
	// not be contained in the pre-release string.  The pre-release version
	// is not appended if it contains invalid characters.
	if appPreRelease != "" {
		version = fmt.Sprintf("%s-%s.%d", version, appPreRelease, appPrereleaseVersion)
	}

	// Append commit hash of current build to version.
	version = fmt.Sprintf("%s commit=%s", version, Commit)

	return version
}
