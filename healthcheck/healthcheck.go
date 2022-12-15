package healthcheck

import (
	"net/http"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

func HealthCheck(r *http.Request) error {
	log.Log.WithName("healthcheck").V(1).Info("Healthcheck passed")
	return nil
}
