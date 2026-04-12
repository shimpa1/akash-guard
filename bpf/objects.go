package bpf

// Load loads the compiled eBPF objects into the kernel.
// It wraps the bpf2go-generated loadTcEgressObjects which is unexported.
func Load() (*TcEgressObjects, error) {
	objs := &TcEgressObjects{}
	if err := loadTcEgressObjects(objs, nil); err != nil {
		return nil, err
	}
	return objs, nil
}
