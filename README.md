# redshift-user-manager
Redshift User Manager (RUM) is a user manager for AWS Redshift.
It can create/delete users and grant/revoke permissions from those users.
RUM works with a roles and permissions model which are defined in a config YAML file.
Permissions define the actual access to schemas/tables.
Permissions are then assigned to roles, and roles can be granted to users.

# Installation
RUM is installed via pip and requires python >= 3.6

```
pip install redshift-user-manager
```
Once installed it can be invoked on the command line with the `rum` command.
```
rum version
```

# Config YAML
RUM must be given a config yaml file which defines: the database that it is operating on, the permissions definitions, and role definitions.
```yaml
host: a-database.abcd1234.us-east-1.redshift.amazonaws.com
port: 5439
database: a-database
roles:
  read-all:
    permissions:
      - r-all
  read-write-all:
    permissions:
      - rw-all
permissions:
  r-all:
    level: READ
    entities: "*"
  rw-all:
    level: READ
    entities: "*"
```

## Permissions
A permission can give access to all tables and schemas, all tables within schema(s), or to specific schema/tables.
```yaml
permissions:
  r-all:
    level: READ
    entities: "*"
  rw-all:
    level: READWRITE
    entities: "*"
  rw-schema-a:
    level: READWRITE
    entities:
      - schema-a.*
  r-table-a:
    level: READ
    entities:
      - schema-a.table-a
  rw-table-a-table-b:
    level: READWRITE
    entities:
      - schema-a.table-a
      - schema-a.table-b
```
### Level
Each permission is given a level: (`READ` or `READWRITE`). This level determines the level of access given to the given entities.

`READ` gives `SELECT` access to the given entities. `READWRITE` gives `ALL` access to the given entities.

### Entities
Each permission must be given value(s) for the entities field. The possible values are `*` or a list of `schema.*` or `schema.table`.
 - `*` will give the given permission level to all tables within all schemas. As well as give default permissions to new entities created by the user which granted these permissions. This is equivalent to explicitly defining `schema.*` for all schemas in the database, and internally executes the same queries as `schema.*`.

 - `schema.*` will give the given permission level to all tables within a specific schemas. As well as give default permissions to new entities created by the user which granted these permissions within that schema.
```sql
GRANT {SELECT|ALL} ON SCHEMA {schema} TO {user_name};
GRANT {USAGE|ALL} ON ALL TABLES IN SCHEMA {schema} TO {user_name};
ALTER DEFAULT PRIVILEGES IN SCHEMA {schema} GRANT {SELECT|ALL} ON TABLES TO {user_name};
```

 - `schema.table` will give the given permission level to a specific table within a specific schema.
```sql
GRANT USAGE ON SCHEMA {schema} TO {user_name};
GRANT {SELECT|ALL} ON {schema}.{table} TO {user_name};
```

## Roles
Roles are lists of permissions that can then be granted or revoked from specific users. Roles are defined in the config YAML.
```yaml
roles:
  developer:
    permissions:
      - r-all
      - rw-schema-a
  read-only:
    permissions:
       - r-all
```
This example config defines two roles: `developer` and `read-only`.

# Usage
RUM is invoked via the command line with the command `rum`. In order to function RUM must be given 4 pieces of information either by environment variable or passed in as a CLI argument:
 - `REDSHIFT_USER_MANAGER_USERNAME`: The username used to connect to the database. This user must be a superuser and is the user that is used to create/grant permissions in the database.
 - `REDSHIFT_USER_MANAGER_PASSWORD`: The password used to connect to the database.
 - `REDSHIFT_USER_MANAGER_CONFIG_FILE`: A path to the `config.yaml` file. Defaults to a file named `redshift-user-manager-config.yaml` in the current working directory.
 - `REDSHIFT_USER_MANAGER_STATE_FILE`: A path to the `state.yaml` file which holds the state for RUM. Defaults to a file named `state.yaml` in the current working directory.

I recommend putting both the state.yaml and config.yaml into source control so that any changes can be change-tracked.

## Create a user.
You can choose to have RUM generate a random password, or you can give it a password to use for the user. When creating a role, you can optionally pass in roles that you want to grant this user. Roles can be granted or revoked in the future as well.

For example, to create a user `test-user` with the password `1234`, and grant it the `read-all` role:
```bash
rum create test-user -p 1234 -r read-all
```

## Delete a user.
When deleting users from redshift, all permissions must first be revoked. RUM handles this for you.

For example, to delete the user `test-user`:
```bash
rum delete test-user
```

## Grant/Revoke roles for/from a user.
Roles can be granted and revoked from a user.

For example, we will first grant the role `r-all` to the user `test-user`, and then revoke it.
```bash
rum grant test-user -r r-all
rum revoke test-user -r r-all
```

## Refresh a user or all users permissions.
When new schemas or tables are added or permissions within the config.yaml change, it can be useful to re-apply all permissions to a single, or all users:

```bash
rum refresh test-user
rum refresh-all


```
