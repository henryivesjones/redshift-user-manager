import asyncio
from functools import wraps
from typing import Iterable, Optional, Tuple

import click

from . import __version__, exceptions
from .constants import (
    _CONFIG_FILE_ENV_VAR,
    _PASSWORD_ENV_VAR,
    _STATE_FILE_ENV_VAR,
    _USERNAME_ENV_VAR,
)
from .redshift_user_manager import RedshiftUserManager


def coro(f):
    """
    Wrapper for async click functions.
    """

    @wraps(f)
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))

    return wrapper


def common_params(func):
    """
    Decorator for common cli options.
    """

    @click.option(
        "--config-file",
        default="redshift-user-manager-config.yaml",
        envvar=_CONFIG_FILE_ENV_VAR,
        help="A path to the config YAML file.",
        show_default=True,
        show_envvar=True,
    )
    @click.option(
        "--state-file",
        default="state.yaml",
        envvar=_STATE_FILE_ENV_VAR,
        show_envvar=True,
        show_default=True,
        help="The state file path which contains the current state.",
    )
    @click.option(
        "--sys-username",
        envvar=_USERNAME_ENV_VAR,
        show_envvar=True,
        help="The username used to connect to the database. Must be a super-user.",
    )
    @click.option(
        "--sys-password",
        envvar=_PASSWORD_ENV_VAR,
        show_envvar=True,
        help="The password used to connect to the database.",
    )
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


@click.group(
    "redshift-user-manager",
    context_settings={"max_content_width": 240, "help_option_names": ["-h", "--help"]},
)
def cli():
    """
    A CLI tool for user management on AWS Redshift. (henryivesjones)

    """
    pass


@cli.command("create")
@coro
@click.argument("user_name")
@click.option("-p", "--password", default=None)
@click.option("-r", "--role", multiple=True)
@common_params
async def create_user(
    user_name: str,
    password: Optional[str],
    role: Iterable[str],
    config_file: str,
    state_file: str,
    sys_username: str,
    sys_password: str,
):
    """
    Create a user in the database. Optionally include roles to assign to the user.
    """
    try:
        async with RedshiftUserManager(
            config_yaml_file=config_file,
            state_yaml_file=state_file,
            username=sys_username,
            password=sys_password,
        ) as rum:
            try:
                password = await rum.create_user(
                    user_name=user_name, roles=list(role), password=password
                )
            except exceptions.UserAlreadyExists:
                raise click.ClickException(
                    f"A user already exists with the username: '{user_name}'"
                )
            click.echo(password)
    except exceptions.RedshiftUserManagerException as e:
        raise click.ClickException(f"{type(e).__name__} {e}")


@cli.command("delete")
@coro
@click.argument("user_name")
@common_params
async def delete_user(
    user_name: str,
    config_file: str,
    state_file: str,
    sys_username: str,
    sys_password: str,
):
    """
    Delete a user from the database.
    """
    try:
        async with RedshiftUserManager(
            config_yaml_file=config_file,
            state_yaml_file=state_file,
            username=sys_username,
            password=sys_password,
        ) as rum:
            try:
                await rum.delete_user(user_name=user_name)
            except exceptions.UserDoesntExist:
                raise click.ClickException(
                    f"No user with the username: '{user_name}' exists."
                )
    except exceptions.RedshiftUserManagerException as e:
        raise click.ClickException(f"{type(e).__name__} {e}")


@cli.command("grant")
@coro
@click.argument("user_name")
@click.option("-r", "--role", multiple=True)
@common_params
async def grant_user(
    user_name: str,
    role: Tuple[str],
    config_file: str,
    state_file: str,
    sys_username: str,
    sys_password: str,
):
    """
    Grant roles to a given user.
    """
    try:
        async with RedshiftUserManager(
            config_yaml_file=config_file,
            state_yaml_file=state_file,
            username=sys_username,
            password=sys_password,
        ) as rum:
            if len(role) == 0:
                return
            try:
                await rum.grant_user_roles(user_name=user_name, roles=list(role))
            except exceptions.UserDoesntExist:
                raise click.ClickException(
                    f"No user with the username: '{user_name}' exists."
                )
            except exceptions.RoleAlreadyGranted as e:
                raise click.ClickException(
                    f"The user '{user_name}' has already been granted the role '{e}'"
                )
    except exceptions.RedshiftUserManagerException as e:
        raise click.ClickException(f"{type(e).__name__} {e}")


@cli.command("revoke")
@coro
@click.argument("user_name")
@click.option("-r", "--role", multiple=True)
@common_params
async def revoke_user(
    user_name: str,
    role: Tuple[str],
    config_file: str,
    state_file: str,
    sys_username: str,
    sys_password: str,
):
    """
    Revoke roles from a given user.
    """
    try:
        async with RedshiftUserManager(
            config_yaml_file=config_file,
            state_yaml_file=state_file,
            username=sys_username,
            password=sys_password,
        ) as rum:
            if len(role) == 0:
                return
            try:
                await rum.revoke_user_roles(user_name=user_name, roles=list(role))
            except exceptions.UserDoesntExist:
                raise click.ClickException(
                    f"No user with the username: '{user_name}' exists."
                )
            except exceptions.RoleDoesntExist as e:
                raise click.ClickException(f"The role '{e}' doesn't exist.")
            except exceptions.RoleNotGranted as e:
                raise click.ClickException(
                    f"The role '{e}' is not granted to '{user_name}'"
                )
    except exceptions.RedshiftUserManagerException as e:
        raise click.ClickException(f"{type(e).__name__} {e}")


@cli.command("refresh")
@coro
@click.argument("user_name")
@click.option("-og", "--only-grant", default=False, is_flag=True)
@common_params
async def refresh_user(
    user_name: str,
    only_grant: bool,
    config_file: str,
    state_file: str,
    sys_username: str,
    sys_password: str,
):
    """
    Refresh permissions for a user. Revokes all permissions, and then grants existing grants.
    """
    try:
        async with RedshiftUserManager(
            config_yaml_file=config_file,
            state_yaml_file=state_file,
            username=sys_username,
            password=sys_password,
        ) as rum:
            try:
                await rum.refresh_user_roles(user_name, only_grant=only_grant)
            except exceptions.UserDoesntExist:
                raise click.ClickException(
                    f"No user with the username: '{user_name}' exists."
                )
    except exceptions.RedshiftUserManagerException as e:
        raise click.ClickException(f"{type(e).__name__} {e}")


@cli.command("ls")
@coro
@common_params
async def get_users(
    config_file: str,
    state_file: str,
    sys_username: str,
    sys_password: str,
):
    """
    List users.
    """
    try:
        async with RedshiftUserManager(
            config_yaml_file=config_file,
            state_yaml_file=state_file,
            username=sys_username,
            password=sys_password,
        ) as rum:
            for user in rum.state.users:
                click.echo(f"{user.user_name} - ({', '.join(user.roles)})")
    except exceptions.RedshiftUserManagerException as e:
        raise click.ClickException(f"{type(e).__name__} {e}")


@cli.command("refresh-all")
@click.option("-og", "--only-grant", default=False, is_flag=True)
@coro
@common_params
async def refresh_all(
    only_grant: bool,
    config_file: str,
    state_file: str,
    sys_username: str,
    sys_password: str,
):
    """
    Refresh permissions for all users.
    """
    try:
        async with RedshiftUserManager(
            config_yaml_file=config_file,
            state_yaml_file=state_file,
            username=sys_username,
            password=sys_password,
        ) as rum:
            for user in rum.state.users:
                click.echo(f"Refreshing {user.user_name}.")
                await rum.refresh_user_roles(user.user_name, only_grant=only_grant)
    except exceptions.RedshiftUserManagerException as e:
        raise click.ClickException(f"{type(e).__name__} {e}")


@cli.command("permissions")
@click.argument("user_name")
@coro
@common_params
async def user_permissions(
    user_name: str,
    config_file: str,
    state_file: str,
    sys_username: str,
    sys_password: str,
):
    """
    List the permissions for a user.
    """
    try:
        async with RedshiftUserManager(
            config_yaml_file=config_file,
            state_yaml_file=state_file,
            username=sys_username,
            password=sys_password,
        ) as rum:
            user = rum.state.get_user(user_name)
            if user is None:
                raise click.ClickException(f"User {user_name} doesn't exist.")
            for permission in rum._get_permissions(user.roles):
                entity = (
                    permission.entities
                    if isinstance(permission.entities, str)
                    else ", ".join(permission.entities)
                )
                click.echo(f"{permission.level} | {entity}")
    except exceptions.RedshiftUserManagerException as e:
        raise click.ClickException(f"{type(e).__name__} {e}")


@cli.command("version")
def version():
    """
    Return the rum version.
    """
    click.echo(f"redshift-user-manager v{__version__}")


def entrypoint():
    cli()


if __name__ == "__main__":
    cli()
