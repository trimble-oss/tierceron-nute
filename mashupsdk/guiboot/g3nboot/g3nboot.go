//go:build g3nboot
// +build g3nboot

package g3nboot

import (
	"log"
	"time"

	"github.com/g3n/engine/app"
	"github.com/g3n/engine/renderer"

	"github.com/faiface/mainthread"
)

func InitMainWindow(initHandler interface{}, runtimeHandler interface{}) {
	log.Printf("G3n Sdk Boot init")
	a := new(app.Application)

	g3nInit := initHandler.(func(a *app.Application))
	mainthread.Run(func() {
		mainthread.Call(func() {
			g3nInit(a)
		})
		g3nRuntimeHandler := runtimeHandler.(func(renderer *renderer.Renderer, deltaTime time.Duration))

		// Run the application -- this will not return.
		mainthread.CallNonBlock(func() {
			a.Run(g3nRuntimeHandler)
		})
	})
}
