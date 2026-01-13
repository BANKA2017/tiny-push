package assets

import "embed"

//go:embed all:fe/*
var EmbeddedFrontend embed.FS

//go:embed all:db/*
var EmbeddedDB embed.FS
