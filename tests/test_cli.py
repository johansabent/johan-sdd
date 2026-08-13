from __future__ import annotations

from johan_sdd.cli import command_descriptors, command_handlers
from johan_sdd.spec_delivery import JOHAN_HOST_ADAPTER


def test_command_descriptors_are_portable_and_registerable_by_the_root_entrypoint() -> None:
    descriptors = command_descriptors()

    assert tuple(descriptor.name for descriptor in descriptors) == ("select-profile", "route")
    assert all(descriptor.argv_prefix == ("johan-sdd", descriptor.name) for descriptor in descriptors)
    assert all(descriptor.exit_codes == (0, 2, 3, 4) for descriptor in descriptors)


def test_handlers_expose_contract_outputs_without_mutating_host_state() -> None:
    handlers = command_handlers()

    profile = handlers["select-profile"]({"requested_profile": "full"})
    route = handlers["route"](
        {
            "files_changed": 1,
            "additions": 1,
            "deletions": 0,
            "change_kinds": ["modify"],
            "observed_surfaces": ["documentation"],
            "primary_checkout": True,
            "working_tree_clean": True,
            "scope": "bounded",
        }
    )

    assert profile["profile"] == "full"
    assert route["lane"] == "micro"


def test_johan_host_adapter_is_optional_metadata_not_a_runtime_dependency() -> None:
    assert JOHAN_HOST_ADAPTER.interface == "johan-host-adapter/v1"
    assert JOHAN_HOST_ADAPTER.phase_router == "using-johan-skills"
    assert JOHAN_HOST_ADAPTER.engineering_flow_hub == "ask-matt"
    assert JOHAN_HOST_ADAPTER.optional is True
