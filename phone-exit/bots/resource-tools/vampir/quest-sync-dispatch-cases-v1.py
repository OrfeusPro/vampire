"""Bounded QuestSync 1854 dispatch through the native receiver and model callsites."""

import struct
from itertools import product


MODEL_MODES = (-2, 0, 1, 2, 0x7FFFFFFF)
GROUP_LAYOUTS = ((), (0,), (1,), (0, 2, 0), (2, 0, 1), (8,), (8,) * 8)
ENTRY_ROUTES = ("registered_trampoline", "direct_receiver")
STATES = (0, 1, 2, 6, 7, 12, 255)
NOTIFICATION_ORDER = ("lookup", "flag", "model", "dispatch")


def scenarios():
    return product(ENTRY_ROUTES, MODEL_MODES, GROUP_LAYOUTS, (0, 1))


def row_projection(pattern, group, item):
    index = group * 8 + item
    if pattern:
        key = 0xFFFFFFFFFFFFFFFF - index
        progress = struct.pack("<6Q", 0x8000000000000000 + index, key, item, group, 0, 1)
    else:
        key = 110120 + index
        progress = struct.pack("<6Q", 1000 + index, item, group, 0, 1, key)
    return dict(group=group, item=item, key=key, state=STATES[(index + pattern) % len(STATES)],
                progress=progress.hex(), argument5=4)


def expected_cases():
    return [
        dict(route=route, mode=mode, groups=list(groups), pattern=pattern,
             final_mode=min(mode, 1),
             resets=["prepare", "storage"] if mode <= 1 else ["storage", "finish"],
             updates=[row_projection(pattern, group, item)
                      for group, size in enumerate(groups) for item in range(size)],
             notifications=list(NOTIFICATION_ORDER), notification_flag=1)
        for route, mode, groups, pattern in scenarios()
    ]


def verify(h, context):
    """Execute the wrapper and receiver. Downstream storage and callbacks are fixtures."""
    uc, x = h.uc, h.x
    handler = int(context["functions"]["handler"], 16)
    receiver = int(context["functions"]["receiver"], 16)
    trampoline = int(context["handler_trampoline"], 16)
    provider = int(context["provider"], 16)
    handler_table = int(context["handler_table"], 16)
    packet_table = int(context["packet_table"], 16)
    callback = int(context["notify_callback"], 16)
    fixtures = {role: int(address, 16) for role, address in context["fixtures"].items()}

    model = h.scratch + 0x1000
    handler_object = h.scratch + 0x2000
    model_table = h.scratch + 0x3000
    packet = h.scratch + 0x3800
    groups_base = h.scratch + 0x4000
    records_base = h.scratch + 0x5000
    notifier = h.scratch + 0x8000
    left_guard, right_guard = b"\xa3" * 16, b"\xa4" * 16

    fixture_state = {}

    def reg(name):
        return uc.reg_read(getattr(x, "UC_X86_REG_" + name))

    def number(at, size=8, *, signed=False):
        return int.from_bytes(uc.mem_read(at, size), "little", signed=signed)

    def require(condition, why):
        if not condition:
            raise ValueError("QuestSync " + why)

    def observe_reset(step):
        observed = fixture_state["resets"]
        want = fixture_state["expected"]["resets"]
        require(len(observed) < len(want) and want[len(observed)] == step,
                "reset sequence differs")
        require(reg("RCX") == model + 0x30, "reset storage argument differs")
        observed.append(step)

    def reset_prepare(_machine):
        observe_reset("prepare")
        require(number(model + 0x78, 4, signed=True) == fixture_state["expected"]["mode"],
                "prepare saw an unexpected model mode")
        h.finish()

    def reset_storage(_machine):
        observe_reset("storage")
        require(reg("RDX") == 0, "storage reset argument differs")
        require(number(model + 0x78, 4, signed=True) == fixture_state["expected"]["mode"],
                "storage reset saw an unexpected model mode")
        h.finish()

    def reset_finish(_machine):
        observe_reset("finish")
        require(number(model + 0x78, 4, signed=True) == 1, "receiver did not normalize model mode")
        h.finish()

    def progress_project(_machine):
        expected = fixture_state["expected"]
        require(fixture_state["resets"] == expected["resets"] and not fixture_state["notifications"],
                "progress call is outside iteration")
        require(fixture_state["pending"] is None, "progress call preceded completion of the prior row")
        index = len(fixture_state["updates"])
        require(index < len(expected["updates"]), "extra progress call")
        wanted = expected["updates"][index]
        address = fixture_state["records"][index]
        destination, key, source = reg("RCX"), reg("RDX"), reg("R8")
        require(destination == reg("RSP") + 0x48 and source == address + 0x18,
                "progress source or output location differs")
        actual = bytes(uc.mem_read(source, 0x30))
        require(key == wanted["key"] and actual.hex() == wanted["progress"],
                "progress key or original bytes differ")
        h.write(destination, actual[:8])
        fixture_state["pending"] = dict(row=wanted, key=key, progress=actual,
                                         progress_out=destination, key_out=None)
        h.finish(destination)

    def key_project(_machine):
        row = fixture_state["pending"]
        require(row is not None and row["key_out"] is None, "key call is outside row projection")
        destination, key = reg("RCX"), reg("RDX")
        require(destination == reg("RSP") + 0x38 and key == row["key"], "key argument differs")
        h.write(destination, struct.pack("<Q", key))
        row["key_out"] = destination
        h.finish(destination)

    def model_apply(_machine):
        row = fixture_state["pending"]
        require(row is not None and row["key_out"] is not None, "virtual application is outside row projection")
        require((reg("RCX"), reg("RDX"), reg("R9")) == (model, row["key_out"], row["progress_out"]),
                "virtual model receiver or projected output differs")
        require(number(row["key_out"]) == row["key"] and
                bytes(uc.mem_read(row["progress_out"], 8)) == row["progress"][:8],
                "projected fixture bytes changed before virtual call")
        state, fifth = reg("R8"), number(reg("RSP") + 0x28, 1)
        require(state == row["row"]["state"] and fifth == 4, "model state or fifth argument differs")
        fixture_state["updates"].append(dict(group=row["row"]["group"], item=row["row"]["item"],
            key=number(row["key_out"]), state=state, progress=row["progress"].hex(), argument5=fifth))
        fixture_state["pending"] = None
        h.finish()

    def observe_notify(step):
        expected = fixture_state["expected"]
        require(fixture_state["updates"] == expected["updates"] and
                fixture_state["resets"] == expected["resets"] and fixture_state["pending"] is None,
                "notification reached before reset or iteration completed")
        observed = fixture_state["notifications"]
        require(len(observed) < len(NOTIFICATION_ORDER) and NOTIFICATION_ORDER[len(observed)] == step,
                "notification sequence differs")
        observed.append(step)

    def notify_lookup(_machine):
        observe_notify("lookup")
        h.finish(notifier)

    def notify_flag(_machine):
        observe_notify("flag")
        flag = reg("RDX")
        require(reg("RCX") == notifier and flag == 1, "notification flag or destination differs")
        fixture_state["notification_flag"] = flag
        h.finish()

    def notify_model(_machine):
        observe_notify("model")
        require(reg("RCX") == model, "notification model differs")
        h.finish()

    def notify_dispatch(_machine):
        observe_notify("dispatch")
        require(reg("RCX") == model + 8 and reg("RDX") == reg("RSP") + 0x98,
                "notification callback arguments differ")
        require(number(reg("RDX")) == callback, "notification callback pointer differs")
        h.finish()

    implementations = dict(reset_prepare=reset_prepare, reset_storage=reset_storage, reset_finish=reset_finish,
                           progress=progress_project, key_wrapper=key_project, model_apply=model_apply,
                           notify_lookup=notify_lookup, notify_flag=notify_flag, notify_model=notify_model,
                           notify_dispatch=notify_dispatch)
    require(set(fixtures) == set(implementations) and set(fixtures.values()) <= h.available_fixtures,
            "fixture roles or admitted caller scope differ")
    for role, fn in implementations.items():
        h.add_fixture(fixtures[role], fn)

    cases = []
    for expected in expected_cases():
        fixture_state.clear()
        fixture_state.update(expected=expected, resets=[], updates=[], notifications=[],
                             notification_flag=None, pending=None, records=[])
        h.reset_regions()
        guarded = []

        def seed(address, payload):
            data = left_guard + payload + right_guard
            uc.mem_write(address - 16, data)
            h.allow_read(address, len(payload))
            guarded.append((address - 16, data))

        mode = expected["mode"]
        seed(model, struct.pack("<Q", model_table) + bytes(0x70) + struct.pack("<i", mode))
        h.allow_write(model + 0x78, 4)
        seed(model_table, bytes(0x48) + struct.pack("<Q", fixtures["model_apply"]))
        seed(handler_object, struct.pack("<Q", handler_table))

        groups = expected["groups"]
        pattern = expected["pattern"]
        group_bytes = bytearray()
        for group, size in enumerate(groups):
            address = records_base + group * 0x400
            payload = bytearray()
            for item in range(size):
                data = row_projection(pattern, group, item)
                payload.extend(struct.pack("<8xQB7x", data["key"], data["state"]))
                payload.extend(bytes.fromhex(data["progress"]))
                fixture_state["records"].append(address + item * 0x48)
            seed(address, bytes(payload))
            group_bytes.extend(struct.pack("<16xQII", address if size or pattern else 0, size, size))
        seed(groups_base, bytes(group_bytes))
        seed(packet, struct.pack("<Q16xQII8x", packet_table, groups_base if groups or pattern else 0,
                                 len(groups), len(groups)))

        entry_addresses = (trampoline, handler, provider, receiver)
        before = [h.entry_counts.get(address, 0) for address in entry_addresses]
        registered = expected["route"] == "registered_trampoline"
        # The decoy has no read permission, so direct receiver cases cannot
        # silently succeed by going through the singleton provider.
        h.set_global(model if registered else notifier)
        if registered:
            h.call(trampoline, handler_object, rdx=notifier, r8=packet)
        else:
            h.call(receiver, model, rdx=packet, r8=notifier)
        entered = [h.entry_counts.get(address, 0) - count
                   for address, count in zip(entry_addresses, before)]
        require(entered == ([1, 1, 1, 1] if registered else [0, 0, 0, 1]),
                "registered or direct native route differs")

        final_mode = number(model + 0x78, 4, signed=True)
        require(final_mode == expected["final_mode"], "final model mode differs")
        for address, initial in guarded:
            if address == model - 16:
                initial = initial[:0x88] + struct.pack("<i", final_mode) + initial[0x8C:]
            require(bytes(uc.mem_read(address, len(initial))) == initial, "input, model or guard bytes changed")

        observed = dict(route=expected["route"], mode=mode, groups=groups, pattern=pattern,
                        final_mode=final_mode, resets=fixture_state["resets"], updates=fixture_state["updates"],
                        notifications=fixture_state["notifications"], notification_flag=fixture_state["notification_flag"])
        require(observed == expected, "observed dispatch trace differs from the case oracle")
        cases.append(observed)
    return dict(cases=cases, metrics=h.validate())
