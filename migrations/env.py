from __future__ import absolute_import, with_statement
from alembic import context
from sqlalchemy import engine_from_config, pool
from logging.config import fileConfig
import logging
from alembic.operations import Operations, MigrateOperation

"""
Alembic extension to generate ALTER TYPE .. ADD VALUE statements to update
SQLAlchemy enums.
"""


import alembic
import alembic.autogenerate
import alembic.autogenerate.render
import alembic.operations.base
import alembic.operations.ops
import sqlalchemy



def get_defined_enums(conn, schema):
    """
    Return a dict mapping PostgreSQL enumeration types to the set of their
    defined values.

    :param conn:
        SQLAlchemy connection instance.

    :param str schema:
        Schema name (e.g. "public").

    :returns dict:
        {
            "my_enum": frozenset(["a", "b", "c"]),
        }
    """
    sql = """
        SELECT
            pg_catalog.format_type(t.oid, NULL),
            ARRAY(SELECT enumlabel
                  FROM pg_catalog.pg_enum
                  WHERE enumtypid = t.oid)
        FROM pg_catalog.pg_type t
        LEFT JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
        WHERE
            t.typtype = 'e'
            AND n.nspname = %s
    """
    return {r[0]: frozenset(r[1]) for r in conn.execute(sql, (schema,))}


def get_declared_enums(metadata, schema, default):
    """
    Return a dict mapping SQLAlchemy enumeration types to the set of their
    declared values.

    :param metadata:
        ...

    :param str schema:
        Schema name (e.g. "public").

    :returns dict:
        {
            "my_enum": frozenset(["a", "b", "c"]),
        }
    """
    types = set(column.type
                for table in metadata.tables.values()
                for column in table.columns
                if (isinstance(column.type, sqlalchemy.Enum) and
                    schema == (column.type.schema or default)))
    return {t.name: frozenset(t.enums) for t in types}


@alembic.operations.base.Operations.register_operation("sync_enum_values")
class SyncEnumValuesOp(alembic.operations.ops.MigrateOperation):
    """
    """
    def __init__(self, schema, name, old_values, new_values):
        self.schema = schema
        self.name = name
        self.old_values = old_values
        self.new_values = new_values

    def reverse(self):
        """
        See MigrateOperation.reverse().
        """
        return SyncEnumValuesOp(self.schema, self.name,
                                old_values=self.new_values,
                                new_values=self.old_values)

    @classmethod
    def sync_enum_values(cls, operations, schema, name, old_values, new_values):
        """
        Define every enum value from `new_values` that is not present in
        `old_values`.

        :param operations:
            ...
        :param str schema:
            Schema name.
        :param name:
            Enumeration type name.
        :param list old_values:
            List of enumeration values that existed in the database before this
            migration executed.
        :param list new_values:
            List of enumeration values that should exist after this migration
            executes.
        """
        with operations.get_bind().connect() as conn:
            conn.execute('COMMIT')
            for value in set(new_values) - set(old_values):
                conn.execute("ALTER TYPE %s.%s ADD VALUE '%s'" % (
                    schema,
                    name,
                    value
                ))


@alembic.autogenerate.render.renderers.dispatch_for(SyncEnumValuesOp)
def render_sync_enum_value_op(autogen_context, op):
    """
    """
    return 'op.sync_enum_values(%r, %r, %r, %r)' % (
        op.schema,
        op.name,
        sorted(op.old_values),
        sorted(op.new_values),
    )


@alembic.autogenerate.comparators.dispatch_for("schema")
def compare_enums(autogen_context, upgrade_ops, schema_names):
    """
    Walk the declared SQLAlchemy schema for every referenced Enum, walk the PG
    schema for every definde Enum, then generate SyncEnumValuesOp migrations
    for each defined enum that has grown new entries when compared to its
    declared version.

    Enums that don't exist in the database yet are ignored, since
    SQLAlchemy/Alembic will create them as part of the usual migration process.
    """
    to_add = set()
    for schema in schema_names:
        default = autogen_context.dialect.default_schema_name
        if schema is None:
            schema = default

        defined = get_defined_enums(autogen_context.connection, schema)
        declared = get_declared_enums(autogen_context.metadata, schema, default)
        for name, new_values in declared.items():
            old_values = defined.get(name)
            # Alembic will handle creation of the type in this migration, so
            # skip undefined names.
            if name in defined and new_values.difference(old_values):
                to_add.add((schema, name, old_values, new_values))

    for schema, name, old_values, new_values in sorted(to_add):
        op = SyncEnumValuesOp(schema, name, old_values, new_values)
        upgrade_ops.ops.append(op)

class ReversibleOp(MigrateOperation):
    def __init__(self, target):
        self.target = target

    @classmethod
    def invoke_for_target(cls, operations, target):
        op = cls(target)
        return operations.invoke(op)

    def reverse(self):
        raise NotImplementedError()

    @classmethod
    def _get_object_from_version(cls, operations, ident):
        version, objname = ident.split(".")

        module = operations.get_context().script.get_revision(version).module
        obj = getattr(module, objname)
        return obj

    @classmethod
    def replace(cls, operations, target, replaces=None, replace_with=None):

        if replaces:
            old_obj = cls._get_object_from_version(operations, replaces)
            drop_old = cls(old_obj).reverse()
            create_new = cls(target)
        elif replace_with:
            old_obj = cls._get_object_from_version(operations, replace_with)
            drop_old = cls(target).reverse()
            create_new = cls(old_obj)
        else:
            raise TypeError("replaces or replace_with is required")

        operations.invoke(drop_old)
        operations.invoke(create_new)


@Operations.register_operation("create_sp", "invoke_for_target")
@Operations.register_operation("replace_sp", "replace")
class CreateSPOp(ReversibleOp):
    def reverse(self):
        return DropSPOp(self.target)


@Operations.register_operation("drop_sp", "invoke_for_target")
class DropSPOp(ReversibleOp):
    def reverse(self):
        return CreateSPOp(self.target)


@Operations.implementation_for(CreateSPOp)
def create_sp(operations, operation):
    operations.execute(
        "CREATE FUNCTION %s %s" % (
            operation.target.name, operation.target.sqltext
        )
    )


@Operations.implementation_for(DropSPOp)
def drop_sp(operations, operation):
    operations.execute("DROP FUNCTION %s" % operation.target.name)


from alembic.operations import Operations, MigrateOperation

@Operations.register_operation("create_sequence")
class CreateSequenceOp(MigrateOperation):
    """Create a SEQUENCE."""

    def __init__(self, sequence_name, schema=None):
        self.sequence_name = sequence_name
        self.schema = schema

    @classmethod
    def create_sequence(cls, operations, sequence_name, **kw):
        """Issue a "CREATE SEQUENCE" instruction."""

        op = CreateSequenceOp(sequence_name, **kw)
        return operations.invoke(op)

    def reverse(self):
        # only needed to support autogenerate
        return DropSequenceOp(self.sequence_name, schema=self.schema)

@Operations.register_operation("drop_sequence")
class DropSequenceOp(MigrateOperation):
    """Drop a SEQUENCE."""

    def __init__(self, sequence_name, schema=None):
        self.sequence_name = sequence_name
        self.schema = schema

    @classmethod
    def drop_sequence(cls, operations, sequence_name, **kw):
        """Issue a "DROP SEQUENCE" instruction."""

        op = DropSequenceOp(sequence_name, **kw)
        return operations.invoke(op)

    def reverse(self):
        # only needed to support autogenerate
        return CreateSequenceOp(self.sequence_name, schema=self.schema)


@Operations.implementation_for(CreateSequenceOp)
def create_sequence(operations, operation):
    if operation.schema is not None:
        name = "%s.%s" % (operation.schema, operation.sequence_name)
    else:
        name = operation.sequence_name
    operations.execute("CREATE SEQUENCE %s" % name)


@Operations.implementation_for(DropSequenceOp)
def drop_sequence(operations, operation):
    if operation.schema is not None:
        name = "%s.%s" % (operation.schema, operation.sequence_name)
    else:
        name = operation.sequence_name
    operations.execute("DROP SEQUENCE %s" % name)


# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
fileConfig(config.config_file_name)
logger = logging.getLogger('alembic.env')

# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata
from flask import current_app
config.set_main_option('sqlalchemy.url',
                       current_app.config.get('SQLALCHEMY_DATABASE_URI'))
target_metadata = current_app.extensions['migrate'].db.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline():
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url, target_metadata=target_metadata, literal_binds=True, compare_type=True)

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """

    # this callback is used to prevent an auto-migration from being generated
    # when there are no changes to the schema
    # reference: http://alembic.zzzcomputing.com/en/latest/cookbook.html
    def process_revision_directives(context, revision, directives):
        if getattr(config.cmd_opts, 'autogenerate', False):
            script = directives[0]
            if script.upgrade_ops.is_empty():
                directives[:] = []
                logger.info('No changes in schema detected.')

    engine = engine_from_config(config.get_section(config.config_ini_section),
                                prefix='sqlalchemy.',
                                poolclass=pool.NullPool)

    connection = engine.connect()
    context.configure(connection=connection,
                      target_metadata=target_metadata,
                      compare_type=True,
                      process_revision_directives=process_revision_directives,
                      **current_app.extensions['migrate'].configure_args)

    try:
        with context.begin_transaction():
            context.run_migrations()
    finally:
        connection.close()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
