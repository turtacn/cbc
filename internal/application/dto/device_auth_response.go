// Package dto provides data transfer objects used in the application layer.
package dto

// DeviceAuthResponse represents the response from the device authorization endpoint.
type DeviceAuthResponse struct {
	DeviceCode      string
	UserCode        string
	VerificationURI string
	ExpiresIn       int
	Interval        int
}
