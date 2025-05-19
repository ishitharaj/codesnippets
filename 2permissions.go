package business

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/kiali/kiali/kubernetes"
	"github.com/kiali/kiali/log"
)

// ResourcePermissions represents the permissions a user has for different resource types
type ResourcePermissions struct {
	// ResourcePermissions maps resource types to allowed verbs
	ResourcePermissions map[string][]string
	// LastChecked is the timestamp when permissions were last checked
	LastChecked time.Time
}

// userPermissionsCache stores user permissions to avoid repeated SubjectAccessReview calls
var userPermissionsCache = struct {
	sync.RWMutex
	permissions map[string]*ResourcePermissions
}{
	permissions: make(map[string]*ResourcePermissions),
}

// CheckUserPermissions checks if a user has permission to access a specific resource
func CheckUserPermissions(ctx context.Context, userClient kubernetes.ClientInterface, username, resourceType, verb string) (bool, error) {
	// Get or check cached permissions
	userPermissionsCache.RLock()
	permissions, exists := userPermissionsCache.permissions[username]
	userPermissionsCache.RUnlock()

	if !exists || time.Since(permissions.LastChecked) > 5*time.Minute {
		// Need to check permissions
		review, err := userClient.GetSelfSubjectAccessReview(ctx, "", "", resourceType, []string{verb})
		if err != nil {
			log.Errorf("Error checking permissions for user %s on resource %s: %v", username, resourceType, err)
			return false, fmt.Errorf("error checking permissions: %w", err)
		}

		if len(review) == 0 {
			return false, nil
		}

		return review[0].Status.Allowed, nil
	}

	// Check cached permissions
	if verbs, ok := permissions.ResourcePermissions[resourceType]; ok {
		for _, v := range verbs {
			if v == verb {
				return true, nil
			}
		}
	}

	return false, nil
}

// CacheUserPermissions caches the permissions for a user
func CacheUserPermissions(username string, permissions *ResourcePermissions) {
	userPermissionsCache.Lock()
	defer userPermissionsCache.Unlock()
	userPermissionsCache.permissions[username] = permissions
}

// GetUserPermissions returns the cached permissions for a user
func GetUserPermissions(username string) *ResourcePermissions {
	userPermissionsCache.RLock()
	defer userPermissionsCache.RUnlock()
	return userPermissionsCache.permissions[username]
}

// ClearUserPermissions clears the cached permissions for a user
func ClearUserPermissions(username string) {
	userPermissionsCache.Lock()
	defer userPermissionsCache.Unlock()
	delete(userPermissionsCache.permissions, username)
}
