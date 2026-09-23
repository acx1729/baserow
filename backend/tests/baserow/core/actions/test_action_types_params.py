import ast
import dataclasses
import inspect
import textwrap

from baserow.core.action.registries import action_type_registry


def test_undo_and_redo_only_read_params_that_exist():
    """
    `undo` and `redo` receive the `Params` that were stored when the action was done.
    Reading an attribute that the `Params` don't have only fails when a user undoes or
    redoes the action, and the action handler then records the error on the action.
    """

    problems = []
    for action_type in action_type_registry.get_all():
        params_class = getattr(action_type, "Params", None)
        if not dataclasses.is_dataclass(params_class):
            continue
        attributes = {field.name for field in dataclasses.fields(params_class)}
        attributes |= set(dir(params_class))

        for method_name in ("undo", "redo"):
            method = getattr(action_type, method_name, None)
            if method is None:
                continue
            tree = ast.parse(textwrap.dedent(inspect.getsource(method)))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Attribute)
                    and isinstance(node.value, ast.Name)
                    and node.value.id == "params"
                    and node.attr not in attributes
                ):
                    problems.append(
                        f"{type(action_type).__name__}.{method_name} reads "
                        f"params.{node.attr}"
                    )

    assert problems == []
