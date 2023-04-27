import asyncio
import logging
import os
import random
from typing import Any, Coroutine, Dict, List, Literal, Optional, Union
from uuid import uuid4

import asyncpg
import click
import yaml
from pydantic import BaseModel, ValidationError

from .exceptions import (
    ConfigDoesntExist,
    InvalidConfig,
    InvalidState,
    PermissionDoesntExist,
    RoleAlreadyGranted,
    RoleDoesntExist,
    RoleNotGranted,
    UmanagedUserAlreadyExists,
    UserAlreadyExists,
    UserDoesntExist,
)

logger = logging.getLogger(__name__)


PermissionLevel = Literal["READ", "READWRITE"]
PermissionLevelRead = "READ"
PermissionLevelReadWrite = "READWRITE"


class Permission(BaseModel):
    """
    Model for a Permission.
    """

    level: PermissionLevel
    entities: Union[Literal["*"], List[str]]


class Role(BaseModel):
    """
    Model for a role.
    """

    permissions: List[str]


class RedshiftUserManagerConfig(BaseModel):
    """
    Model for the config yaml file.
    """

    host: str
    port: int
    database: str
    roles: Dict[str, Role]
    permissions: Dict[str, Permission]


class UserState(BaseModel):
    """
    Model for the state yaml file.
    """

    user_name: str
    roles: List[str]


class RedshiftUserManagerState(BaseModel):
    """
    Interface for interacting with the state.
    """

    users: List[UserState]

    def get_user(self, user_name: str) -> Optional[UserState]:
        """
        Get a user from the state by name.

        Args:
            user_name (str): The user name of the user to get.

        Returns:
            Optional[UserState]: Returns None if the user is not found. Returns a UserState object if it is found.
        """
        try:
            return self.users[[user.user_name for user in self.users].index(user_name)]
        except ValueError:
            return None

    def create_user(self, user_name: str, roles: List[str]) -> None:
        """
        Create a user entry in the state.

        Args:
            user_name (str): The name of the user.
            roles (List[str]): The list of role names to grant to the user.
        """
        self.users.append(UserState(user_name=user_name, roles=roles))

    def grant_user(self, user_name: str, roles: List[str]) -> None:
        """
        Grant roles to a given user.

        Args:
            user_name (str): The user to grant the roles to.
            roles (List[str]): The list of role names to grant to the user.

        Raises:
            UserDoesntExist: Raised when the given user does not exist.
        """
        user = self.get_user(user_name)
        if user is None:
            raise UserDoesntExist(user_name)
        user.roles += roles

    def revoke_user(self, user_name: str, roles: List[str]) -> None:
        """
        Revoke roles from a given user.

        Args:
            user_name (str): The user to revoke the roles from.
            roles (List[str]): The roles to revoke from the user.

        Raises:
            UserDoesntExist: Raised when the given user does not exist.
        """
        user = self.get_user(user_name)
        if user is None:
            raise UserDoesntExist(user_name)
        user.roles = [role for role in user.roles if role not in roles]

    def delete_user(self, user_name: str) -> None:
        """
        Remove a user from the state.

        Args:
            user_name (str): The user to remove from the state.
        Raises:
            UserDoesntExist: Raised when the given user does not exist.
        """
        try:
            user_index = [user.user_name for user in self.users].index(user_name)
        except ValueError:
            raise UserDoesntExist(user_name)
        self.users.pop(user_index)


class RedshiftUserManager:
    """
    A class for orchestrating user creation/deletion and role granting/revoking.
    """

    concurrency: int
    username: str
    password: str
    config: RedshiftUserManagerConfig
    state: RedshiftUserManagerState
    state_yaml_file: str
    config_yaml_file: str
    pool: asyncpg.Pool

    def __init__(
        self,
        config_yaml_file: str,
        username: str,
        password: str,
        state_yaml_file: str,
        concurrency: int = 1
    ):
        self.concurrency = concurrency
        self.config = RedshiftUserManager.parse_config_yaml(config_yaml_file)
        self.state_yaml_file = state_yaml_file
        self.state = RedshiftUserManager.parse_state_yaml(state_yaml_file)
        self.username = username
        self.password = password

    async def __aenter__(self):
        self.pool = await asyncpg.create_pool(
            host=self.config.host,
            port=self.config.port,
            user=self.username,
            password=self.password,
            database=self.config.database,
            max_size=self.concurrency,
            min_size=1,
        )
        return self

    async def __aexit__(self, _, __, ___):
        self._persist_state()
        await self.pool.close()

    async def delete_user(self, user_name: str):
        """
        Delete a user from the database.
          1. Revoke all permissions from the user in the database.
          2. Drop the user from the database.
          3. Delete the user from the rum state.

        Args:
            user_name (str): The user to drop.

        Raises:
            UserDoesntExist: Raised when the given user does not exist.
        """
        if user_name not in [user.user_name for user in self.state.users]:
            raise UserDoesntExist(user_name)
        await self._revoke_all_permissions(user_name)
        await self._db_drop_user(user_name)
        self.state.delete_user(user_name)

    async def create_user(
        self, user_name: str, roles: List[str] = [], password: Optional[str] = None
    ) -> str:
        """
        Creates a user in the database. If no password is provided then a random one will be created.
        Optionally include roles to assign to this user. Roles an be granted or revoked later.

        Args:
            user_name (str): The name of the user.
            roles (List[str], optional): A list of role names to grant to the user. Defaults to [].
            password (Optional[str], optional): The password for this user, if not provided a random password will be created. Defaults to None.

        Raises:
            UserAlreadyExists: Raised when a user already exists and is managed by rum.
            UmanagedUserAlreadyExists: Raised when a user already exists in the database which is not managed by rum.

        Returns:
            str: The password for this user.
        """
        if self.state.get_user(user_name) is not None:
            raise UserAlreadyExists(user_name)
        if password is None:
            password = RedshiftUserManager.generate_password()
        permissions = self._get_permissions(roles)
        try:
            await self._db_create_user(user_name, password)
        except asyncpg.exceptions.DuplicateObjectError:
            raise UmanagedUserAlreadyExists(user_name)
        await self._grant_permissions(user_name, permissions)

        self.state.create_user(user_name, roles)

        return password

    async def update_user_password(
        self, user_name: str, password: Optional[str]
    ) -> str:
        """
        Update the password for a given user.

        Args:
            user_name (str): The user to update the password for.
            password (Optional[str]): The password to set for the user. If none is provided then a random one will be generated.

        Raises:
            UserDoesntExist: Raised when the given user does not exist.

        Returns:
            str: The password that was set for the user.
        """
        user = self.state.get_user(user_name)
        if user is None:
            raise UserDoesntExist(user_name)
        if password is None:
            password = RedshiftUserManager.generate_password()

        await self._db_update_user_password(user_name, password)

        return password

    async def grant_user_roles(self, user_name: str, roles: List[str] = []):
        """
        Grant roles to a given user.

        Args:
            user_name (str): The user to grant the roles to.
            roles (List[str], optional): The role names to grant to the user. Defaults to [].

        Raises:
            UserDoesntExist: Raised when the given user does not exist.
            RoleDoesntExist: Raised when a role referenced does not exist.
            RoleAlreadyGranted: Raised when a role has already been granted to the given user.
        """
        user = self.state.get_user(user_name)
        if user is None:
            raise UserDoesntExist(user_name)
        for role in roles:
            if role not in self.config.roles:
                raise RoleDoesntExist(role)
            if role in user.roles:
                raise RoleAlreadyGranted(role)

        permissions = self._get_permissions(roles)
        await self._grant_permissions(user_name, permissions)
        self.state.grant_user(user_name, roles)

    async def revoke_user_roles(self, user_name: str, roles: List[str] = []):
        """
        Revoke roles from a given user.

        Args:
            user_name (str): The user to revoke the roles from.
            roles (List[str], optional): The roles names to revoke from the user. Defaults to [].

        Raises:
            UserDoesntExist: Raised when the given user does not exist.
            RoleDoesntExist: Raised when a role referenced does not exist.
            RoleNotGranted: Raised when a role in the revoke list cannot be revoked because it is not granted to the given user.
        """
        user = self.state.get_user(user_name)
        if user is None:
            raise UserDoesntExist(user_name)

        for role in roles:
            if role not in self.config.roles:
                raise RoleDoesntExist(role)
            if role not in user.roles:
                raise RoleNotGranted(role)

        self.state.revoke_user(user_name, roles)
        await self.refresh_user_roles(user_name)

    async def refresh_user_roles(self, user_name: str, only_grant: bool = False):
        """
        Refresh the permissions for a given user.

          1. (only_grant == False) Revoke all permissions from user
          2. Grant all permissions assigned to user.

        Args:
            user_name (str): The user to refresh permissions for.
            only_grant (bool, optional): Skip the revoke step. Defaults to False.

        Raises:
            UserDoesntExist: Raised when the given user does not exist.
        """
        user = self.state.get_user(user_name)
        if user is None:
            raise UserDoesntExist(user_name)
        if not only_grant:
            await self._revoke_all_permissions(user_name)
        permissions = self._get_permissions(user.roles)
        await self._grant_permissions(user_name, permissions)

    async def _grant_permissions(self, user_name: str, permissions: List[Permission]):
        """
        Grant permissions to a given user. Performs all grants in parallel using a connection pool.

        Args:
            user_name (str): The user to grant permissions for.
            permissions (List[Permission]): The permissions to grant.
        """
        tasks: List[Coroutine[Any, Any, None]] = []
        for permission in permissions:
            tasks += await self._db_grant_permission(user_name, permission)

        with click.progressbar(
            asyncio.as_completed(tasks), length=len(tasks), label="Granting Permissions"
        ) as wrapped_tasks:
            for task in wrapped_tasks:
                await task

    async def _revoke_all_permissions(self, user_name: str):
        """
        Revokes all permissions from a given user. Performs all revokes in parallel using a connection pool.

        Args:
            user_name (str): The user to revoke the permissions for.
        """
        tasks = await self._db_revoke_all(user_name)
        with click.progressbar(
            asyncio.as_completed(tasks), length=len(tasks), label="Revoking Permissions"
        ) as wrapped_tasks:
            for task in wrapped_tasks:
                await task

    async def _db_grant_permission(
        self, user_name: str, permission: Permission
    ) -> List[Coroutine[Any, Any, None]]:
        """
        Grant a permission to a given user. Returns a list of coroutines which must be awaited.

        Args:
            user_name (str): The user to grant the permission to.
            permission (Permission): The permission to grant.

        Returns:
            List[Coroutine[Any, Any, None]]: A list of coroutines which are performing the actual DB operations. Must be awaited.
        """
        tasks: List[Coroutine[Any, Any, None]] = []
        if permission.entities == "*":
            tasks += await self._db_grant_all(user_name, permission.level)
            return tasks

        for entity in permission.entities:
            schema, table = entity.split(".")
            if table == "*":
                tasks.append(self._db_grant_schema(schema, user_name, permission.level))
                continue
            tasks.append(
                self._db_grant_table(schema, table, user_name, permission.level)
            )
        return tasks

    async def _db_grant_all(
        self, user_name: str, level: PermissionLevel
    ) -> List[Coroutine[Any, Any, None]]:
        """
        Grant the given permission level to the given user for all schemas.

        Args:
            user_name (str): The user to grant the permissions to.
            level (PermissionLevel): The level for the grant.

        Returns:
            List[Coroutine[Any, Any, None]]: A list of coroutines which are performing the actual DB operations. Must be awaited.
        """
        schemas = await self._db_get_schemas()
        tasks: List[Coroutine[Any, Any, None]] = []
        for schema in schemas:
            tasks.append(self._db_grant_schema(schema, user_name, level))
        return tasks

    async def _db_revoke_all(self, user_name: str) -> List[Coroutine[Any, Any, None]]:
        """
        Revoke all permissions from all schemas for a given user.

        Args:
            user_name (str): The given user to revoke permissions for.

        Returns:
            List[Coroutine[Any, Any, None]]: A list of coroutines which are performing the actual DB operations. Must be awaited.
        """
        schemas = await self._db_get_schemas()
        tasks: List[Coroutine[Any, Any, None]] = []
        for schema in schemas:
            tasks.append(self._db_revoke_all_schema(schema, user_name))
        return tasks

    async def _db_update_user_password(self, user_name: str, password: str):
        query = f"""
ALTER USER "{user_name}" WITH PASSWORD '{password}';;
        """.strip()
        async with self.pool.acquire() as conn:
            await conn.execute(query)

    async def _db_grant_schema(
        self, schema: str, user_name: str, level: PermissionLevel
    ) -> None:
        schema_level = "USAGE" if level == PermissionLevelRead else "ALL"
        table_level = "SELECT" if level == PermissionLevelRead else "ALL"
        query = f"""
GRANT {schema_level} ON SCHEMA {schema} TO "{user_name}";
GRANT {table_level} ON ALL TABLES IN SCHEMA {schema} TO "{user_name}";
ALTER DEFAULT PRIVILEGES IN SCHEMA {schema} GRANT {table_level} ON TABLES TO "{user_name}";
        """.strip()
        async with self.pool.acquire() as conn:
            await conn.execute(query)

    async def _db_grant_table(
        self, schema: str, table: str, user_name: str, level: PermissionLevel
    ):
        table_level = "SELECT" if level == PermissionLevelRead else "ALL"
        query = f"""
GRANT USAGE ON SCHEMA {schema} TO "{user_name}";
GRANT {table_level} ON {schema}.{table} TO "{user_name}";
        """
        async with self.pool.acquire() as conn:
            await conn.execute(query)

    async def _db_create_user(self, user_name: str, password: str):
        query = f"""
CREATE USER "{user_name}" PASSWORD '{password}';
        """.strip()
        async with self.pool.acquire() as conn:
            await conn.execute(query)

    async def _db_drop_user(self, user_name: str):
        query = f"""
DROP USER "{user_name}";
        """.strip()
        async with self.pool.acquire() as conn:
            await conn.execute(query)

    async def _db_revoke_all_schema(self, schema: str, user_name: str) -> None:
        query = f"""
REVOKE ALL ON ALL TABLES IN SCHEMA {schema} FROM "{user_name}";
REVOKE ALL ON SCHEMA {schema} FROM "{user_name}";
ALTER DEFAULT PRIVILEGES IN SCHEMA {schema} REVOKE ALL ON TABLES from "{user_name}";
        """.strip()
        async with self.pool.acquire() as conn:
            await conn.execute(query)

    async def _db_get_schemas(self) -> List[str]:
        query = """
select nspname as schema
from pg_catalog.pg_namespace
where nspname = 'public' or nspowner > 1;
        """.strip()
        async with self.pool.acquire() as conn:
            results = await conn.fetch(query)
        return [row[0] for row in results]

    def _get_permissions(self, roles: List[str] = []) -> List[Permission]:
        """
        Return the permissions related to a list of roles.

        Args:
            roles (List[str], optional): The list of role names to get permissions for. Defaults to [].

        Raises:
            RoleDoesntExist: Raised when a role that is referenced does not exist.
            PermissionDoesntExist: Raised when a permission referenced by a role does not exist.

        Returns:
            List[Permission]: A list of Permission objects that should be granted given the input roles.
        """
        permissions: List[Permission] = []
        permission_names: List[str] = []
        for role_name in roles:
            role = self.config.roles.get(role_name)
            if role is None:
                raise RoleDoesntExist(role_name)
            for permission_name in role.permissions:
                permission = self.config.permissions.get(permission_name)
                if permission is None:
                    raise PermissionDoesntExist(permission_name)

                if permission_name in permission_names:
                    continue
                permissions.append(permission)
                permission_names.append(permission_name)
        return permissions

    def _persist_state(self) -> None:
        """
        Persists the current state to the state yaml file.
        Creating it if it doesn't exist yet and overwriting it if it does.
        """
        with open(self.state_yaml_file, "w") as f:
            yaml.dump(self.state.dict(), f)

    @staticmethod
    def parse_state_yaml(state_yaml_file: str) -> RedshiftUserManagerState:
        """
        Parse a rum  state yaml file and return a RedshiftUserManagerState object.

        Args:
            state_yaml_file (str): A path to a YAML file

        Raises:
            InvalidState: Raised when the state does not pass validation.

        Returns:
            RedshiftUserManagerState: An object describing the current rum state.
        """
        if not os.path.exists(state_yaml_file):
            return RedshiftUserManagerState(users=[])
        with open(state_yaml_file, "r") as f:
            state_yaml = f.read()
        try:
            state = yaml.safe_load(state_yaml)
        except yaml.YAMLError as e:
            raise InvalidState(e)
        try:
            return RedshiftUserManagerState(**state)
        except ValidationError as e:
            raise InvalidState(e)

    @staticmethod
    def parse_config_yaml(config_yaml_file: str) -> RedshiftUserManagerConfig:
        """
        Parse a rum config yaml file and return a RedshiftUserManagerConfig object.

        Args:
            config_yaml_file (str): A path to a YAML file

        Raises:
            ConfigDoesntExist: Raised when the given path does not point to a file.
            InvalidConfig: Raised when the config does not pass validation.

        Returns:
            RedshiftUserManagerConfig: An object describing the configuration.
        """
        if not os.path.exists(config_yaml_file):
            raise ConfigDoesntExist(config_yaml_file)
        with open(config_yaml_file, "r") as f:
            config_yaml = f.read()
        try:
            config = yaml.safe_load(config_yaml)
        except yaml.YAMLError as e:
            raise InvalidConfig(e)
        try:
            return RedshiftUserManagerConfig(**config)
        except ValidationError as e:
            raise InvalidConfig(e)

    @staticmethod
    def generate_password() -> str:
        """
        Generate a random password

        Returns:
            str: The generated password
        """
        return "".join(
            [
                char if index % random.randint(2, 4) != 0 else char.upper()
                for index, char in enumerate(uuid4().hex)
            ]
        )
