class RedshiftUserManagerException(Exception):
    """
    All RUM exceptions inherit from this exception.
    """


class InvalidConfig(RedshiftUserManagerException):
    """
    Raised when the config yaml file is invalid
    """


class ConfigDoesntExist(RedshiftUserManagerException):
    """
    Raised when the config yaml file doesn't exist.
    """


class InvalidState(RedshiftUserManagerException):
    """
    Raised when the state yaml file is invalid
    """


class UserAlreadyExists(RedshiftUserManagerException):
    """
    Raised when a user already exists that is managed by redshift-user-manager
    """


class UmanagedUserAlreadyExists(RedshiftUserManagerException):
    """
    Raised when a user already exists that is unmanaged by redshift-user-manager
    """


class UserDoesntExist(RedshiftUserManagerException):
    """
    Raised when trying to perform an action on a non-existent user.
    """


class RoleDoesntExist(RedshiftUserManagerException):
    """
    Raised when a non-existent role is referenced
    """


class RoleAlreadyGranted(RedshiftUserManagerException):
    """
    Raised when a role is granted to a user which already has the role.
    """


class RoleNotGranted(RedshiftUserManagerException):
    """
    Raised when a role is not granted to a user and it is referenced in the context of that user.
    """


class PermissionDoesntExist(RedshiftUserManagerException):
    """
    Raised when a permission doesnt exist.
    """
