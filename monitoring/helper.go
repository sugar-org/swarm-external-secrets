package monitoring

import (
	"math"

	log "github.com/sirupsen/logrus"
)

func uint64ToInt64(value uint64) int64 {
	if value <= math.MaxInt64 {
		return int64(value)
	}
	log.Warnf("Value %d exceeds int64 limit, using max value", value)
	return math.MaxInt64
}
