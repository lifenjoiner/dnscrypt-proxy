package main

import (
	_ "embed"
)

// MainHTMLTemplate - templates and static files using go:embed
//
//go:embed static/templates/dashboard.html
var MainHTMLTemplate string

//go:embed static/js/monitoring.js
var MonitoringJSContent string
