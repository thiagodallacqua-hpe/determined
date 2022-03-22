package cluster

import (
	"context"
	"sync"
	"time"

	"github.com/determined-ai/determined/master/internal/db"
	log "github.com/sirupsen/logrus"
	"github.com/uptrace/bun"
)

type ClusterID struct {
	bun.BaseModel `bun:"table:cluster_id"`

	ClusterID        string    `bun:"cluster_id,notnull"`
	ClusterHeartbeat time.Time `bun:"cluster_heartbeat,notnull"`
}

var theLastBootMutex sync.Mutex
var theLastBootClusterHeartbeat *time.Time

func InitTheLastBootClusterHeartbeat() {
	theLastBootMutex.Lock()
	defer theLastBootMutex.Unlock()

	if theLastBootClusterHeartbeat != nil {
		log.Warn("detected re-initialization of the last boot cluster heartbeat ts")
	}

	cluster_id := new(ClusterID)
	err := db.Bun().NewSelect().Model(cluster_id).Scan(context.TODO())
	if err != nil {
		log.WithError(err).Warn("failed to init the last boot cluster heartbeat")
		return
	}

	theLastBootClusterHeartbeat = &cluster_id.ClusterHeartbeat
}

func TheLastBootClusterHeartbeat() *time.Time {
	return theLastBootClusterHeartbeat
}
