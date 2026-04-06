package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"opc-ua-centralserver/centralserver"
)

func main() {
	process := centralserver.NewProcess(centralserver.ProcessConfig{
		Host:        "127.0.0.1",
		GeneralPort: 4842,
		SCADAPort:   4844,
		HTTPPort:    8080,
		DemoMode:    true,
	})
	process.SetIdentifyCallback(func(ctx centralserver.IdentifyContext) {
		log.Printf("identify callback: found=%t vendor=%d module=%d serial=%d", ctx.Found, ctx.Identity.VendorID, ctx.Identity.ModuleType, ctx.Identity.SerialNumber)
	})
	process.SetEnrollCallback(func(ctx centralserver.EnrollmentContext) {
		log.Printf("enroll callback: array=%s index=%d vendor=%d module=%d serial=%d", ctx.Enrollment.Kind, ctx.Enrollment.Index, ctx.Identity.VendorID, ctx.Identity.ModuleType, ctx.Identity.SerialNumber)
	})

	if err := process.Start(); err != nil {
		log.Fatal(err)
	}
	defer process.Stop()

	log.Printf("general OPC UA server running on opc.tcp://%s:%d", process.Config.Host, process.Config.GeneralPort)
	log.Printf("SCADA OPC UA server running on opc.tcp://%s:%d", process.Config.Host, process.Config.SCADAPort)
	log.Printf("HTTP health interface running on http://%s:%d/health", process.Config.Host, process.Config.HTTPPort)
	log.Printf("HTTP admin interface running on http://%s:%d/admin", process.Config.Host, process.Config.HTTPPort)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	log.Println("shutdown requested")
}
