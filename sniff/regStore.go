package sniff

import "log"

func (store regStore) Append(key uint32, p packetInfo) error {
	if _, ok := store[key]; !ok {
		store[key] = make([]packetInfo, 32)
	}
	store[key] = append(store[key], p)
	return nil
}

func (r *registry) Process(key uint32) {
	r.rwm.RLock()
	defer r.rwm.RUnlock()
	info, ok := r.store[key]
	if !ok {
		return
	}
	for k, v := range info {
		log.Printf("k: %#+v\n", k)
		log.Printf("v: %#+v\n", v)

		log.Println("\n\n ")
	}
}
