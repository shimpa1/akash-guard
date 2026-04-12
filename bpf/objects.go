package bpf

// Load loads the compiled eBPF objects into the kernel.
func Load() (*TcEgressObjects, error) {
	objs := &TcEgressObjects{}
	if err := LoadTcEgressObjects(objs, nil); err != nil {
		return nil, err
	}
	return objs, nil
}
