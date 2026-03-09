package cmd

// ProxyCmd is the top-level proxy command group.
type ProxyCmd struct {
	Serve ProxyServeCmd `cmd:"" help:"Start filtered Gmail proxy (holds credentials in memory)"`
}
