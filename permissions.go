package kubernetes

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// UserPermissions represents the permissions a user has based on their ClusterRole
type UserPermissions struct {
	// Resources is a map of resource types to their allowed verbs
	Resources map[string][]string
	// APIGroups is a map of API groups to their allowed resources
	APIGroups map[string][]string
}

// GetUserPermissions retrieves the permissions for a given user by checking their ClusterRoleBindings
func GetUserPermissions(k8s kubernetes.Interface, username string) (*UserPermissions, error) {
	permissions := &UserPermissions{
		Resources: make(map[string][]string),
		APIGroups: make(map[string][]string),
	}

	// Get all ClusterRoleBindings
	crbs, err := k8s.RbacV1().ClusterRoleBindings().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list ClusterRoleBindings: %w", err)
	}

	// Find ClusterRoleBindings for this user
	for _, crb := range crbs.Items {
		for _, subject := range crb.Subjects {
			if subject.Kind == "User" && subject.Name == username {
				// Get the ClusterRole
				cr, err := k8s.RbacV1().ClusterRoles().Get(context.TODO(), crb.RoleRef.Name, metav1.GetOptions{})
				if err != nil {
					return nil, fmt.Errorf("failed to get ClusterRole %s: %w", crb.RoleRef.Name, err)
				}

				// Process rules
				for _, rule := range cr.Rules {
					// Process API groups
					for _, apiGroup := range rule.APIGroups {
						if apiGroup == "*" {
							apiGroup = "core" // Use "core" for the core API group
						}
						permissions.APIGroups[apiGroup] = append(permissions.APIGroups[apiGroup], rule.Resources...)
					}

					// Process resources
					for _, resource := range rule.Resources {
						if resource == "*" {
							// Handle wildcard resources
							permissions.Resources["*"] = rule.Verbs
						} else {
							permissions.Resources[resource] = rule.Verbs
						}
					}
				}
			}
		}
	}

	return permissions, nil
}

// HasPermission checks if a user has permission to perform an action on a resource
func (p *UserPermissions) HasPermission(apiGroup, resource, verb string) bool {
	// Check if user has wildcard permissions
	if verbs, ok := p.Resources["*"]; ok {
		for _, v := range verbs {
			if v == "*" || v == verb {
				return true
			}
		}
	}

	// Check specific resource permissions
	if verbs, ok := p.Resources[resource]; ok {
		for _, v := range verbs {
			if v == "*" || v == verb {
				// Check if the resource is allowed in the API group
				if apiGroup == "core" {
					apiGroup = ""
				}
				if allowedResources, ok := p.APIGroups[apiGroup]; ok {
					for _, allowedResource := range allowedResources {
						if allowedResource == "*" || allowedResource == resource {
							return true
						}
					}
				}
			}
		}
	}

	return false
}

// FilterResources filters a list of resources based on user permissions
func (p *UserPermissions) FilterResources(apiGroup, resourceType string, resources []interface{}) []interface{} {
	if !p.HasPermission(apiGroup, resourceType, "list") {
		return []interface{}{}
	}

	filtered := make([]interface{}, 0)
	for _, resource := range resources {
		// Here you would implement specific filtering logic based on the resource type
		// For now, we just check if the user has permission to view the resource type
		filtered = append(filtered, resource)
	}

	return filtered
}
