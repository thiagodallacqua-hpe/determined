package task

import (
	"github.com/determined-ai/determined/master/pkg/actor"
	"github.com/determined-ai/determined/master/pkg/model"
)

var allocationMap map[model.AllocationID]*actor.Ref

func InitAllocationMap() {
	allocationMap = map[model.AllocationID]*actor.Ref{}
}

func GetAllocation(allocationID model.AllocationID) *actor.Ref {
	return allocationMap[allocationID]
}

func RegisterAllocation(allocationID model.AllocationID, ref *actor.Ref) {
	allocationMap[allocationID] = ref
}

func DeregisterAllocation(allocationID model.AllocationID) {
	delete(allocationMap, allocationID)
}
