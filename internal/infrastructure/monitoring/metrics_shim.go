package monitoring

// The real Metrics struct already exists in this package.
// We add methods so callers don't rely on internal fields.

// path/method/status are here to future-proof label sets.

func (m *Metrics) ActiveRequestsInc(path, method string) {}
func (m *Metrics) ActiveRequestsDec(path, method string) {}

func (m *Metrics) ObserveRequestDuration(path, method string, status int, seconds float64) {}

func (m *Metrics) IncRequestErrors(path, method string, status int) {}
