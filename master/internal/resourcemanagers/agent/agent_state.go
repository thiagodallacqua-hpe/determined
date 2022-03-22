package agent

import (
	"context"
	"fmt"
	"strconv"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/uptrace/bun"

	"github.com/determined-ai/determined/master/internal/db"
	"github.com/determined-ai/determined/master/internal/sproto"
	"github.com/determined-ai/determined/master/internal/task"
	"github.com/determined-ai/determined/master/pkg/actor"
	"github.com/determined-ai/determined/master/pkg/aproto"
	"github.com/determined-ai/determined/master/pkg/cproto"
	"github.com/determined-ai/determined/master/pkg/device"
	"github.com/determined-ai/determined/master/pkg/model"
)

type slotEnabled struct {
	deviceAdded  bool
	agentEnabled bool
	userEnabled  bool
	draining     bool
}

func (s slotEnabled) enabled() bool {
	return s.agentEnabled && s.userEnabled
}

type slot struct {
	device    device.Device
	enabled   slotEnabled
	container *cproto.Container
}

func (s *slot) summarize() model.SlotSummary {
	return model.SlotSummary{
		ID:        strconv.Itoa(int(s.device.ID)),
		Device:    s.device,
		Enabled:   s.enabled.enabled(),
		Container: s.container,
		Draining:  s.enabled.draining,
	}
}

// AgentState holds the scheduler state for an agent. The implementation of agent-related operations
// (e.g., socket I/O) is deferred to the actor.
type AgentState struct {
	// Handler is agent actor reference.
	Handler          *actor.Ref
	Devices          map[device.Device]*cproto.ID
	Label            string
	resourcePoolName string
	enabled          bool
	draining         bool
	uuid             uuid.UUID

	// Since we only model GPUs as devices/slots and assume each slot can be allocated with
	// one container, we add one additional field to keep track of zero-slot containers.
	// We need this field to know if the agent is idle.
	ZeroSlotContainers    map[cproto.ID]bool
	maxZeroSlotContainers int

	slotStates map[device.ID]*slot
	containers map[cproto.ID]*actor.Ref
}

// NewAgentState returns a new agent empty agent state backed by the handler.
func NewAgentState(msg sproto.AddAgent, maxZeroSlotContainers int) *AgentState {
	return &AgentState{
		Handler:               msg.Agent,
		Label:                 msg.Label,
		Devices:               make(map[device.Device]*cproto.ID),
		ZeroSlotContainers:    make(map[cproto.ID]bool),
		maxZeroSlotContainers: maxZeroSlotContainers,
		enabled:               true,
		slotStates:            make(map[device.ID]*slot),
		containers:            make(map[cproto.ID]*actor.Ref),
		uuid:                  uuid.New(),
	}
}

func (a *AgentState) string() string {
	return a.Handler.Address().Local()
}

// NumSlots returns the total number of slots available.
func (a *AgentState) NumSlots() int {
	switch {
	case a.draining:
		return a.NumUsedSlots()
	case !a.enabled:
		return 0
	default:
		return len(a.Devices)
	}
}

// NumEmptySlots returns the number of slots that have not been allocated to containers.
func (a *AgentState) NumEmptySlots() (slots int) {
	switch {
	case a.draining, !a.enabled:
		return 0
	default:
		return a.NumSlots() - a.NumUsedSlots()
	}
}

// NumUsedSlots returns the number of slots that have been allocated to containers.
func (a *AgentState) NumUsedSlots() (slots int) {
	for _, id := range a.Devices {
		if id != nil {
			slots++
		}
	}
	return slots
}

// NumUsedZeroSlots returns the number of allocated zero-slot units.
func (a *AgentState) NumUsedZeroSlots() int {
	return len(a.ZeroSlotContainers)
}

// NumZeroSlots returns the total number of zero-slot units.
func (a *AgentState) NumZeroSlots() int {
	switch {
	case a.draining:
		return a.NumUsedZeroSlots()
	case !a.enabled:
		return 0
	default:
		return a.maxZeroSlotContainers
	}
}

// NumEmptyZeroSlots returns the number of unallocated zero-slot units.
func (a *AgentState) NumEmptyZeroSlots() int {
	switch {
	case a.draining || !a.enabled:
		return 0
	default:
		return a.NumZeroSlots() - a.NumUsedZeroSlots()
	}
}

// Idle signals if the agent is idle.
func (a *AgentState) Idle() bool {
	return a.NumUsedZeroSlots() == 0 && a.NumUsedSlots() == 0
}

// AllocateFreeDevices allocates devices.
func (a *AgentState) AllocateFreeDevices(slots int, id cproto.ID) ([]device.Device, error) {
	if slots == 0 {
		a.ZeroSlotContainers[id] = true
		return nil, nil
	}
	cid := id
	devices := make([]device.Device, 0, slots)
	for d, dcid := range a.Devices {
		if dcid == nil {
			devices = append(devices, d)
		}
		if len(devices) == slots {
			break
		}
	}

	if len(devices) != slots {
		return nil, errors.New("not enough devices")
	}

	for _, d := range devices {
		a.Devices[d] = &cid
	}

	return devices, nil
}

// DeallocateContainer deallocates containers.
func (a *AgentState) DeallocateContainer(id cproto.ID) {
	delete(a.ZeroSlotContainers, id)
	for d, cid := range a.Devices {
		if cid != nil && *cid == id {
			a.Devices[d] = nil
		}
	}
}

// DeepCopy returns a copy of agentState for scheduler internals.
func (a *AgentState) DeepCopy() *AgentState {
	copiedAgent := &AgentState{
		Handler:               a.Handler,
		Label:                 a.Label,
		Devices:               make(map[device.Device]*cproto.ID),
		ZeroSlotContainers:    make(map[cproto.ID]bool),
		maxZeroSlotContainers: a.maxZeroSlotContainers,
		enabled:               a.enabled,
		draining:              a.draining,
		// TODO(ilia): Deepcopy of `slotStates` may be necessary one day.
		slotStates: a.slotStates,
	}

	for originalDevice, id := range a.Devices {
		copiedDevice := device.Device{
			ID:    originalDevice.ID,
			Brand: originalDevice.Brand,
			UUID:  originalDevice.UUID,
			Type:  originalDevice.Type,
		}
		copiedAgent.Devices[copiedDevice] = id
	}

	for originalKey, originalValue := range a.ZeroSlotContainers {
		copiedAgent.ZeroSlotContainers[originalKey] = originalValue
	}

	return copiedAgent
}

// Enable enables the agent.
func (a *AgentState) Enable(ctx *actor.Context) {
	ctx.Log().Infof("enabling agent: %s", a.string())
	a.enabled = true
	a.draining = false
}

// Disable disables or drains the agent.
func (a *AgentState) Disable(ctx *actor.Context, drain bool) {
	drainStr := "disabling"
	if drain {
		drainStr = "draining"
	}
	ctx.Log().Infof("%s agent: %s", drainStr, a.string())
	a.draining = drain
	a.enabled = false
}

func (a *AgentState) addDevice(ctx *actor.Context, device device.Device, containerID *cproto.ID) {
	ctx.Log().Infof("adding device: %s on %s", device.String(), a.string())
	a.Devices[device] = containerID
}

func (a *AgentState) removeDevice(ctx *actor.Context, device device.Device) {
	ctx.Log().Infof("removing device: %s (%s)", device.String(), a.string())
	delete(a.Devices, device)
}

// agentStarted initializes slots from AgentStarted.Devices.
func (a *AgentState) agentStarted(ctx *actor.Context, agentStarted *aproto.AgentStarted) {
	msg := agentStarted
	for _, d := range msg.Devices {
		enabled := slotEnabled{
			agentEnabled: true,
			userEnabled:  true,
		}
		a.slotStates[d.ID] = &slot{enabled: enabled, device: d}
		a.updateSlotDeviceView(ctx, d.ID)
	}

	if err := a.persist(); err != nil {
		fmt.Println("PERSIST FAILURE")
	}
}

func (a *AgentState) containerStateChanged(ctx *actor.Context, msg aproto.ContainerStateChanged) {
	for _, d := range msg.Container.Devices {
		s, ok := a.slotStates[d.ID]
		if !ok {
			ctx.Log().Warnf("bad containerStateChanged on device: %d (%s)", d.ID, a.string())
			continue
		}

		s.container = &msg.Container
		if msg.Container.State == cproto.Terminated {
			s.container = nil
		}
	}

	if err := a.persist(); err != nil {
		fmt.Println("PERSIST FAILURE")
	}

	updateContainerState(&msg.Container)
}

func (a *AgentState) startContainer(ctx *actor.Context, msg sproto.StartTaskContainer) error {
	inner := func(deviceId device.ID) error {
		s, ok := a.slotStates[deviceId]
		if !ok {
			return errors.New("can't find slot")
		}

		// TODO(ilia): Potential race condition if slot is disabled in-between scheduling?
		if !s.enabled.enabled() {
			return errors.New("container allocated but slot is not enabled")
		}
		if s.container != nil {
			return errors.New("container already allocated to slot")
		}

		s.container = &msg.StartContainer.Container

		return nil
	}

	for _, d := range msg.StartContainer.Container.Devices {
		if err := inner(d.ID); err != nil {
			return errors.Wrapf(err, "bad startContainer on device: %d (%s)", d.ID, a.string())
		}
	}

	a.containers[msg.Container.ID] = msg.TaskActor
	if err := a.persist(); err != nil {
		fmt.Println("PERSIST FAILURE")
	}
	updateContainerState(&msg.StartContainer.Container)

	return nil
}

func (a *AgentState) getSlotsSummary(ctx *actor.Context) model.SlotsSummary {
	summary := make(model.SlotsSummary, len(a.slotStates))
	for deviceID, slotState := range a.slotStates {
		summary[fmt.Sprintf("%s/slots/%d", ctx.Self().Address(), deviceID)] = slotState.summarize()
	}

	return summary
}

func (a *AgentState) updateSlotDeviceView(ctx *actor.Context, deviceID device.ID) {
	s, ok := a.slotStates[deviceID]
	if !ok {
		ctx.Log().Warnf("bad updateSlotDeviceView on device: %d (%s): not found", deviceID, a.string())
		return
	}

	// TODO(ilia): Don't materialize `Devices` view on slots.
	if s.enabled.enabled() && !s.enabled.deviceAdded {
		s.enabled.deviceAdded = true

		var containerID *cproto.ID
		if s.container != nil {
			containerID = &s.container.ID
		}

		a.addDevice(ctx, s.device, containerID)
	} else if !s.enabled.enabled() {
		if !s.enabled.draining && s.enabled.deviceAdded {
			s.enabled.deviceAdded = false
			a.removeDevice(ctx, s.device)
		}

		// On `PostStop`, draining will be already set to false, and we'll kill the container
		// whether we have the device or not.
		if !s.enabled.draining && s.container != nil {
			ctx.Self().System().TellAt(s.container.Parent, task.Kill)
		}
	}
}

func (a *AgentState) patchSlotStateInner(
	ctx *actor.Context, msg PatchSlotState, slotState *slot) model.SlotSummary {
	if msg.Enabled != nil {
		slotState.enabled.userEnabled = *msg.Enabled
	}
	if msg.Drain != nil {
		slotState.enabled.draining = *msg.Drain
	}
	a.updateSlotDeviceView(ctx, slotState.device.ID)

	return slotState.summarize()
}

func (a *AgentState) patchAllSlotsState(
	ctx *actor.Context, msg PatchAllSlotsState) model.SlotsSummary {
	result := model.SlotsSummary{}
	for _, slotState := range a.slotStates {
		summary := a.patchSlotStateInner(
			ctx, PatchSlotState{
				ID:      slotState.device.ID, // Note: this is effectively unused.
				Enabled: msg.Enabled,
				Drain:   msg.Drain,
			},
			slotState)
		result[summary.ID] = summary
	}
	return result
}

func (a *AgentState) patchSlotState(
	ctx *actor.Context, msg PatchSlotState) (model.SlotSummary, error) {
	s, ok := a.slotStates[msg.ID]
	if !ok {
		return model.SlotSummary{}, errors.New(
			fmt.Sprintf("bad updateSlotDeviceView on device: %d (%s): not found", msg.ID, a.string()))
	}
	return a.patchSlotStateInner(ctx, msg, s), nil
}

func (a *AgentState) snapshot() *AgentSnapshot {
	slotData := make([]SlotData, 0, len(a.slotStates))
	for _, slotState := range a.slotStates {
		slotData = append(slotData, SlotData{
			Device:      slotState.device,
			UserEnabled: slotState.enabled.userEnabled,
			Container:   slotState.container,
		})
	}

	zeroSlotData := make([]cproto.ID, 0, len(a.ZeroSlotContainers))
	for cid := range a.ZeroSlotContainers {
		zeroSlotData = append(zeroSlotData, cid)
	}

	s := AgentSnapshot{
		AgentID:          a.Handler.Address().Local(),
		UUID:             a.uuid.String(),
		ResourcePoolName: a.resourcePoolName,
		UserEnabled:      a.enabled,  // TODO: not 100% user-driven
		UserDraining:     a.draining, // TODO: not 100% user-driven
		Slots:            slotData,
		ZeroSlots:        zeroSlotData,
	}

	return &s
}

func (a *AgentState) persist() error {
	snapshot := a.snapshot()
	_, err := db.Bun().NewInsert().Model(snapshot).
		On("CONFLICT (uuid) DO UPDATE").
		On("CONFLICT (agent_id) DO UPDATE").
		Exec(context.TODO())
	return err
}

func (a *AgentState) restore() error {
	snapshot := AgentSnapshot{}
	err := db.Bun().NewSelect().Model(&snapshot).
		Where("agent_id = ?", a.Handler.Address().Local()).
		Scan(context.TODO())
	if err != nil {
		return err
	}
	fmt.Println("restored: ", snapshot)

	return nil
}

func (a *AgentState) delete() error {
	_, err := db.Bun().NewDelete().Model((*AgentSnapshot)(nil)).
		Where("agent_id = ?", a.Handler.Address().Local()).
		Exec(context.TODO())
	if err != nil {
		return err
	}
	fmt.Println("deleted agent state:", a.Handler.Address().Local())
	return nil
}

func (a *AgentState) clearUnlessRecovered(recovered map[cproto.ID]aproto.ContainerReattachAck) {
	updated := false
	for d := range a.Devices {
		if cID := a.Devices[d]; cID != nil {
			_, ok := recovered[*cID]
			if !ok {
				a.Devices[d] = nil
				a.slotStates[d.ID].container = nil
				updated = true
			}
		}
	}

	if updated {
		a.persist()
	}
}

type AgentID = string

func RetrieveAgentStates() (map[AgentID]AgentState, error) {
	snapshots := []AgentSnapshot{}
	if err := db.Bun().NewSelect().Model(&snapshots).Scan(context.TODO()); err != nil {
		return nil, err
	}

	result := make(map[AgentID]AgentState, len(snapshots))

	for _, s := range snapshots {
		state, err := NewAgentStateFromSnapshot(s)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to recreate agent state %s", s.AgentID)
		}

		result[s.AgentID] = *state
	}

	return result, nil
}

func NewAgentStateFromSnapshot(as AgentSnapshot) (*AgentState, error) {
	// TODO XXX
	parsedUUID, err := uuid.Parse(as.UUID)
	if err != nil {
		return nil, err
	}

	slotStates := make(map[device.ID]*slot)
	devices := make(map[device.Device]*cproto.ID)
	zeroSlotContainers := make(map[cproto.ID]bool)

	//containerIDs := []cproto.ID{}

	for _, sd := range as.Slots {
		slotStates[sd.Device.ID] = &slot{
			device:    sd.Device,
			container: sd.Container,
			enabled: slotEnabled{
				deviceAdded:  true,
				agentEnabled: as.UserEnabled,  // TODO
				userEnabled:  as.UserEnabled,  // TODO
				draining:     as.UserDraining, // TODO
			},
		}
		if sd.Container != nil {
			devices[sd.Device] = &sd.Container.ID
			//containerIDs = append(containerIDs, sd.Container.ID)
		} else {
			devices[sd.Device] = nil
		}
	}

	for _, cid := range as.ZeroSlots {
		zeroSlotContainers[cid] = true
	}

	result := AgentState{
		Label: "", // TODO
		// TODO for resource pool name
		// TODO max zero slot containers should come from resource pool I guess
		maxZeroSlotContainers: 100,
		resourcePoolName:      as.ResourcePoolName,
		uuid:                  parsedUUID,
		enabled:               as.UserEnabled,
		draining:              as.UserDraining,
		slotStates:            slotStates,
		Devices:               devices,
		ZeroSlotContainers:    zeroSlotContainers,
		containers:            make(map[cproto.ID]*actor.Ref),
	}

	return &result, nil
}

func (a *AgentState) restoreContainersField() error {
	// TODO XXX restore from... addresses?
	containerIDs := []cproto.ID{}

	for k := range a.Devices {
		if a.Devices[k] != nil {
			containerIDs = append(containerIDs, *a.Devices[k])
		}
	}

	c2a, err := loadContainersToAllocationIds(containerIDs)
	if err != nil {
		return err
	}

	containers := make(map[cproto.ID]*actor.Ref)
	for contID := range c2a {
		ref := task.GetAllocation(c2a[contID])
		if ref != nil {
			containers[contID] = ref
		}
	}
	fmt.Println("containers map size:", len(containers))

	a.containers = containers

	return nil
}

func ClearAgentStates(agentIds []AgentID) error {
	_, err := db.Bun().NewDelete().Where("agent_id in (?)", agentIds).Exec(context.TODO())

	return err
}

func updateContainerState(c *cproto.Container) error {
	snapshot := NewContainerSnapshot(c)
	_, err := db.Bun().NewUpdate().Model(&snapshot).
		Where("container_id = ?", snapshot.ID).
		Column("state", "devices").
		Exec(context.TODO())

	return err
}

func loadContainersToAllocationIds(containerIDs []cproto.ID) (map[cproto.ID]model.AllocationID, error) {
	cs := []ContainerSnapshot{}
	result := []map[string]interface{}{}
	rr := map[cproto.ID]model.AllocationID{}

	if len(containerIDs) == 0 {
		return rr, nil
	}

	err := db.Bun().NewSelect().Model(&cs).
		Join("JOIN allocation_resources al_res ON al_res.resource_id = rmac.resource_id").
		Where("container_id IN (?)", bun.In(containerIDs)).
		Column("container_id", "allocation_id").
		Scan(context.TODO(), &result)
	if err != nil {
		return nil, err
	}
	fmt.Println("loadContainersToAllocationIDs result", result)

	for _, row := range result {
		rr[cproto.ID(row["container_id"].(string))] = model.AllocationID(row["allocation_id"].(string))
	}

	fmt.Println("loadContainersToAllocationIDs rr ", rr)

	return rr, nil
}
