from rest_framework import permissions

class AllowAnyCreationAnsIsAuthenticatedForOthers(permissions.BasePermission):
    def has_permission(self, request, view):
        if view.action == 'create':
            # Allow unauthenticated access for the create action
            return True
        # Use the default IsAuthenticated permission for other actions
        return permissions.IsAuthenticated().has_permission(request, view)