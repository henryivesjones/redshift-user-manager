import asyncio
import logging
import os
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
    level: PermissionLevel
    entities: Union[Literal["*"], List[str]]

    class Config:
        use_enum_values = True


class Role(BaseModel):
    permissions: List[str]


class RedshiftUserManagerConfig(BaseModel):
    host: str
    port: int
    database: str
    roles: Dict[str, Role]
    permissions: Dict[str, Permission]


class UserState(BaseModel):
    user_name: str
    roles: List[str]


class RedshiftUserManagerState(BaseModel):
    users: List[UserState]

    def get_user(self, user_name: str):
        try:
            return self.users[[user.user_name for user in self.users].index(user_name)]
        except ValueError:
            return None

    def create_user(self, user_name: str, roles: List[str]):
        self.users.append(UserState(user_name=user_name, roles=roles))

    def grant_user(self, user_name: str, roles: List[str]):
        user_state = self.users[
            [user.user_name for user in self.users].index(user_name)
        ]
        user_state.roles += roles

    def revoke_user(self, user_name: str, roles: List[str]):
        user_state = self.users[
            [user.user_name for user in self.users].index(user_name)
        ]
        user_state.roles = [role for role in user_state.roles if role not in roles]

    def delete_user(self, user_name: str):
        user_index = [user.user_name for user in self.users].index(user_name)
        self.users.pop(user_index)


class RedshiftUserManager:
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
    ):
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
            max_size=20,
        )
        return self

    async def __aexit__(self, _, __, ___):
        self._persist_state()
        await self.pool.close()

    async def delete_user(self, user_name: str):
        if user_name not in [user.user_name for user in self.state.users]:
            raise UserDoesntExist(user_name)
        await self._revoke_all_permissions(user_name)
        await self._db_drop_user(user_name)
        self.state.delete_user(user_name)

    async def create_user(
        self, user_name: str, roles: List[str] = [], password: Optional[str] = None
    ) -> str:
        if user_name in [user.user_name for user in self.state.users]:
            raise UserAlreadyExists(user_name)
        if password is None:
            password = "".join(
                [
                    char if index % 3 != 0 else char.upper()
                    for index, char in enumerate(uuid4().hex)
                ]
            )
        permissions = self._get_permissions(roles)
        try:
            await self._db_create_user(user_name, password)
        except asyncpg.exceptions.DuplicateObjectError:
            raise UmanagedUserAlreadyExists(user_name)
        await self._grant_permissions(user_name, permissions)

        self.state.create_user(user_name, roles)

        return password

    async def grant_user_roles(self, user_name: str, roles: List[str] = []):
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
        user = self.state.get_user(user_name)
        if user is None:
            raise UserDoesntExist(user_name)
        if not only_grant:
            await self._revoke_all_permissions(user_name)
        permissions = self._get_permissions(user.roles)
        await self._grant_permissions(user_name, permissions)

    async def _grant_permissions(self, user_name: str, permissions: List[Permission]):
        tasks: List[Coroutine[Any, Any, None]] = []
        for permission in permissions:
            tasks += await self._db_grant_permission(user_name, permission)

        with click.progressbar(
            asyncio.as_completed(tasks), length=len(tasks), label="Granting Permissions"
        ) as wrapped_tasks:
            for task in wrapped_tasks:
                await task

    async def _revoke_all_permissions(self, user_name):
        tasks = await self._db_revoke_all(user_name)
        with click.progressbar(
            asyncio.as_completed(tasks), length=len(tasks), label="Revoking Permissions"
        ) as wrapped_tasks:
            for task in wrapped_tasks:
                await task

    async def _db_grant_permission(self, user_name: str, permission: Permission):
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

    async def _db_grant_all(self, user_name: str, level: PermissionLevel):
        schemas = await self._db_get_schemas()
        tasks: List[Coroutine[Any, Any, None]] = []
        for schema in schemas:
            tasks.append(self._db_grant_schema(schema, user_name, level))
        return tasks

    async def _db_revoke_all(self, user_name: str):
        schemas = await self._db_get_schemas()
        tasks: List[Coroutine[Any, Any, None]] = []
        for schema in schemas:
            tasks.append(self._db_revoke_all_schema(schema, user_name))
        return tasks

    async def _db_grant_schema(
        self, schema: str, user_name: str, level: PermissionLevel
    ):
        schema_level = "USAGE" if level == PermissionLevelRead else "ALL"
        table_level = "SELECT" if level == PermissionLevelRead else "ALL"
        query = f"""
GRANT {schema_level} ON SCHEMA {schema} TO {user_name};
GRANT {table_level} ON ALL TABLES IN SCHEMA {schema} TO {user_name};
ALTER DEFAULT PRIVILEGES IN SCHEMA {schema} GRANT {table_level} ON TABLES TO {user_name};
        """.strip()
        async with self.pool.acquire() as conn:
            await conn.execute(query)

    async def _db_grant_table(
        self, schema: str, table: str, user_name: str, level: PermissionLevel
    ):
        table_level = "SELECT" if level == PermissionLevelRead else "ALL"
        query = f"""
GRANT USAGE ON SCHEMA {schema} TO {user_name};
GRANT {table_level} ON {schema}.{table} TO {user_name};
        """
        async with self.pool.acquire() as conn:
            await conn.execute(query)

    async def _db_create_user(self, user_name: str, password: str):
        query = f"""
CREATE USER {user_name} PASSWORD '{password}';
        """.strip()
        async with self.pool.acquire() as conn:
            await conn.execute(query)

    async def _db_drop_user(self, user_name: str):
        query = f"""
DROP USER {user_name};
        """.strip()
        async with self.pool.acquire() as conn:
            await conn.execute(query)

    async def _db_revoke_all_schema(self, schema: str, user_name: str):
        query = f"""
REVOKE ALL ON ALL TABLES IN SCHEMA {schema} FROM {user_name};
REVOKE ALL ON SCHEMA {schema} FROM {user_name};
ALTER DEFAULT PRIVILEGES IN SCHEMA {schema} REVOKE ALL ON TABLES from {user_name};
        """.strip()
        async with self.pool.acquire() as conn:
            await conn.execute(query)

    async def _db_get_schemas(self):
        query = """
select nspname as schema
from pg_catalog.pg_namespace
where nspname = 'public' or nspowner > 1;
        """.strip()
        async with self.pool.acquire() as conn:
            results = await conn.fetch(query)
        return [row[0] for row in results]

    def _get_permissions(self, roles: List[str] = []) -> List[Permission]:
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

    def _persist_state(self):
        with open(self.state_yaml_file, "w") as f:
            yaml.dump(self.state.dict(), f)

    @staticmethod
    def parse_state_yaml(state_yaml_file: str) -> RedshiftUserManagerState:
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
