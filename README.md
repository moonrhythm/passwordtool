# passwordtool

[![Build Status](https://travis-ci.org/moonrhythm/passwordtool.svg?branch=master)](https://travis-ci.org/moonrhythm/passwordtool)
[![codecov](https://codecov.io/gh/moonrhythm/passwordtool/branch/master/graph/badge.svg)](https://codecov.io/gh/moonrhythm/passwordtool)
[![Go Report Card](https://goreportcard.com/badge/github.com/moonrhythm/passwordtool)](https://goreportcard.com/report/github.com/moonrhythm/passwordtool)
[![GoDoc](https://godoc.org/github.com/moonrhythm/passwordtool?status.svg)](https://godoc.org/github.com/moonrhythm/passwordtool)

Password hashing and comparing tool

## Install

`go get github.com/moonrhythm/passwordtool`

## Usage

```go
hashed, err := passwordtool.Hash("superman")
if err != nil {
	// ...
}
fmt.Println(hashed)

equal, err := passwordtool.Compare(hashed, "superman")
if err != nil {
	// ...
}
fmt.Println(equal)
```

## Specific algorithm

```go
hc := passwordtool.Bcrypt{Cost: 11}
hashed, err := hc.Hash("superman")
if err != nil {
	// ...
}

equal, err := hc.Compare(hashed, "superman")
if err != nil {
	// ...
}
fmt.Println(equal)

// or

equal, err = passwordtool.Compare(hashed, "superman")
if err != nil {
	// ...
}
fmt.Println(equal)
```
