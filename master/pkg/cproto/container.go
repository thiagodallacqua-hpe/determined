package cproto

import (
	"github.com/determined-ai/determined/master/pkg/check"
	"github.com/determined-ai/determined/master/pkg/device"
	"github.com/determined-ai/determined/proto/pkg/containerv1"
	"github.com/determined-ai/determined/proto/pkg/devicev1"
)

// Container tracks a container running in the cluster.
type Container struct {
	ID      ID              `json:"id"`
	State   State           `json:"state"`
	Devices []device.Device `json:"devices"`
}

// Transition transitions the container state to the new state. An illegal transition will panic.
func (c Container) Transition(new State) Container {
	check.Panic(c.State.checkTransition(new))
	return Container{
		ID: c.ID, State: new, Devices: c.Devices}
}

// DeviceUUIDsByType returns the UUIDs of the devices with the given device type.
func (c Container) DeviceUUIDsByType(deviceType device.Type) (uuids []string) {
	for _, d := range c.Devices {
		if d.Type == deviceType {
			uuids = append(uuids, d.UUID)
		}
	}

	return uuids
}

// Proto returns the proto representation of the container.
func (c *Container) Proto() *containerv1.Container {
	if c == nil {
		return nil
	}
	var devices []*devicev1.Device
	for _, d := range c.Devices {
		devices = append(devices, d.Proto())
	}
	return &containerv1.Container{
		Id:      c.ID.String(),
		State:   c.State.Proto(),
		Devices: devices,
	}
}

// DeepCopy returns the proto representation of the container.
func (c *Container) DeepCopy() *Container {
	if c == nil {
		return nil
	}

	devices := make([]device.Device, len(c.Devices))
	copy(devices, c.Devices)

	return &Container{
		ID:      c.ID,
		State:   c.State,
		Devices: devices,
	}
}
