package g3ndisplay

import (
	"github.com/g3n/engine/window"
	"github.com/trimble-oss/tierceron-nute-core/mashupsdk"
)

type IG3nDisplayRenderer interface {
	Render(window *window.GlfwWindow, displayHint *mashupsdk.MashupDisplayHint) *mashupsdk.MashupDisplayHint
}
