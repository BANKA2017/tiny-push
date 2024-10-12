package assets

import "embed"

//go:embed all:fe/*
var EmbeddedFrontent embed.FS
