from augur.state.graph import StateGraph, _MAX_VALUES_PER_KEY


def test_records_id_shaped_keys():
    g = StateGraph()
    g.record_response({"id": 1, "user_id": 2, "uuid": "abc"}, "ep1", owner="alice")
    assert g.values_for("id")
    assert g.values_for("user_id")
    assert g.values_for("uuid")


def test_ignores_non_id_keys():
    g = StateGraph()
    g.record_response({"name": "bob", "email": "b@x"}, "ep1", owner="alice")
    assert g.by_key == {}


def test_walks_nested():
    g = StateGraph()
    g.record_response(
        {"items": [{"id": 1}, {"id": 2}], "meta": {"thing_id": 99}},
        "ep",
        owner="alice",
    )
    assert {o.value for o in g.values_for("id")} == {1, 2}
    assert any(o.value == 99 for o in g.values_for("thing_id"))


def test_cross_owner_pairs_only_other_owner():
    g = StateGraph()
    g.record_response({"id": 1}, "ep", owner="alice")
    g.record_response({"id": 2}, "ep", owner="bob")
    pairs = g.cross_owner_pairs("id")
    # alice's id=1 is offered to bob, bob's id=2 is offered to alice.
    # nothing offered to its own owner.
    targets = [(o.value, other) for o, other in pairs]
    assert (1, "bob") in targets
    assert (2, "alice") in targets
    assert all(other != o.seen_owner for o, other in pairs)


def test_per_key_cap():
    g = StateGraph()
    for i in range(_MAX_VALUES_PER_KEY + 50):
        g.record_response({"id": i}, "ep", owner="alice")
    assert len(g.values_for("id")) == _MAX_VALUES_PER_KEY
