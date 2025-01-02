module github.com/trimble-oss/tierceron-nute

go 1.23.2

require (
	gioui.org v0.7.1
	github.com/g3n/engine v0.2.0
	golang.org/x/mobile v0.0.0-20231127183840-76ac6878050a
	google.golang.org/grpc v1.69.2
	google.golang.org/protobuf v1.35.1
)

require golang.org/x/exp/shiny v0.0.0-20240707233637-46b078467d37 // indirect

require (
	fyne.io/systray v1.10.1-0.20220621085403-9a2652634e93 // indirect
	gioui.org/cpu v0.0.0-20210817075930-8d6a761490d2 // indirect
	gioui.org/shader v1.0.8 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fredbi/uri v0.0.0-20181227131451-3dcfdacbaaf3 // indirect
	github.com/fsnotify/fsnotify v1.5.4 // indirect
	github.com/fyne-io/gl-js v0.0.0-20220119005834-d2da28d9ccfe // indirect
	github.com/fyne-io/glfw-js v0.0.0-20220120001248-ee7290d23504 // indirect
	github.com/fyne-io/image v0.0.0-20220602074514-4956b0afb3d2 // indirect
	github.com/go-gl/gl v0.0.0-20211210172815-726fda9656d6 // indirect
	github.com/go-text/typesetting v0.1.1 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/goki/freetype v0.0.0-20181231101311-fa8a33aabaff // indirect
	github.com/golang/freetype v0.0.0-20170609003504-e2365dfdc4a0 // indirect
	github.com/gopherjs/gopherjs v1.17.2 // indirect
	github.com/jsummers/gobmp v0.0.0-20151104160322-e2ba15ffa76e // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/srwiley/oksvg v0.0.0-20200311192757-870daf9aa564 // indirect
	github.com/srwiley/rasterx v0.0.0-20200120212402-85cb7272f5e9 // indirect
	github.com/stretchr/testify v1.9.0 // indirect
	github.com/tevino/abool v1.2.0 // indirect
	github.com/yuin/goldmark v1.4.13 // indirect
	//golang.org/x/net v0.0.0-20220708220712-1185a9018129 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/genproto v0.0.0-20230410155749-daa745c078e1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	honnef.co/go/js/dom v0.0.0-20210725211120-f030747120f2 // indirect
)

require (
	fyne.io/fyne/v2 v2.1.3
	golang.org/x/exp v0.0.0-20240707233637-46b078467d37 // indirect
	golang.org/x/image v0.21.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
)

//require github.com/go-gl/glfw/v3.3.2/glfw v0.0.0-20211213063430-748e38ca8aec

require (
	github.com/faiface/mainthread v0.0.0-20171120011319-8b78f0a41ae3
	github.com/go-gl/glfw/v3.3/glfw v0.0.0-20231223183121-56fa3ac82ce7
	golang.org/x/net v0.33.0 // indirect
)

// Uncomment for local development
// replace fyne.io/fyne/v2 v2.1.3 => ../../fyne // Use mashup_v1 branch

// replace gioui.org v0.0.0-20220318070519-8833a6738a3b => ../../gio // Use mashup_v1 branch

//replace github.com/g3n/engine v0.2.0 => ../g3n/engine // Use mashup_v1 branch

// replace github.com/fyne-io/glfw-js v0.0.0-20220120001248-ee7290d23504 => ../../glfw-js // Use mashup_v1 branch

replace fyne.io/fyne/v2 v2.1.3 => github.com/mrjrieke/fyne/v2 v2.1.3-6

replace gioui.org v0.0.0-20220318070519-8833a6738a3b => github.com/mrjrieke/gio v0.0.0-20220406132257-ec1380c11ef0

replace github.com/g3n/engine v0.2.0 => github.com/mrjrieke/engine v0.2.1-0.20230107141038-8bd28c2897c4

replace github.com/fyne-io/glfw-js v0.0.0-20220120001248-ee7290d23504 => github.com/mrjrieke/glfw-js v0.0.0-20220409154018-95a896685cdb
