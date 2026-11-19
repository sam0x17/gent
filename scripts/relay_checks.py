"""Shared synthetic MCP relay checks for local and two-machine proofs."""


def exercise_turns(intermediary, target, attachment_id, files, wait_for, restart):
    first = {"attachment_id": attachment_id, "request_id": intermediary.request_id(),
             "text": "  preserve this relay turn exactly\n", "files": files}
    sent = intermediary.call("gent_relay_send_non_blocking", first)[0]
    first_id = sent["turn_id"]
    second_id = intermediary.call("gent_relay_send_non_blocking", {
        "attachment_id": attachment_id, "request_id": intermediary.request_id(),
        "text": "a separate follow-up turn", "files": []})[0]["turn_id"]
    wait_for(lambda: (target.call("gent_relay_next")[0] or {}).get("request", {}).get("id") == first_id)
    next_turn, raw = target.call("gent_relay_next")
    assert next_turn["request"]["text"] == first["text"]
    assert next_turn["request"]["files"] == files
    assert any(part["type"] == "image" and part["data"] == files[0]["data_base64"] for part in raw["content"])
    assert [m["id"] for m in target.call("gent_inbox")[0]] == [first_id]
    target.call("gent_ack", {"message_id": first_id})
    target.call("gent_reply", {"message_id": first_id, "request_id": target.request_id(), "text": "cannot bypass relay state"}, error=True)
    progress = {"turn_id": first_id, "request_id": target.request_id(),
                "text": "progress with exact image", "files": files, "outcome": "progress"}
    target.call("gent_relay_respond", progress)

    def status(turn):
        return intermediary.call("gent_relay_turn_status", {"turn_id": turn})[0]

    wait_for(lambda: len(status(first_id)["responses"]) == 1)
    restart()
    assert status(first_id)["state"] == "pending"
    assert target.call("gent_relay_next")[0]["request"]["id"] == first_id
    assert intermediary.call("gent_relay_send_non_blocking", first)[0]["duplicate"] is True
    history = intermediary.call("gent_relay_turns")[0]["turns"]
    assert [turn["turn_id"] for turn in history] == [first_id, second_id]
    assert all(turn["relay"]["attachment_id"] == attachment_id for turn in history)
    target.call("gent_relay_respond", dict(progress, turn_id=second_id, request_id=target.request_id()), error=True)
    cancel = {"turn_id": first_id, "request_id": intermediary.request_id()}
    intermediary.call("gent_relay_cancel", cancel)
    assert status(first_id)["state"] == "pending"
    wait_for(lambda: target.call("gent_relay_next")[0]["cancel_requested"])
    target.call("gent_relay_respond", {"turn_id": first_id, "request_id": target.request_id(),
                                      "text": "cancellation handled", "outcome": "cancelled"})
    wait_for(lambda: status(first_id)["state"] == "completed")
    assert status(first_id)["responses"][-1]["relay"]["kind"] == "cancelled"
    assert intermediary.call("gent_relay_cancel", cancel)[0]["duplicate"] is True
    for response in status(first_id)["responses"]:
        intermediary.call("gent_ack", {"message_id": response["id"]})
    assert target.call("gent_relay_next")[0]["request"]["id"] == second_id
    target.call("gent_ack", {"message_id": second_id})
    final = {"turn_id": second_id, "request_id": target.request_id(),
             "text": "final with image", "files": files, "outcome": "complete"}
    target.call("gent_relay_respond", final)
    assert target.call("gent_relay_respond", final)[0]["duplicate"] is True
    wait_for(lambda: status(second_id)["state"] == "completed")
    value, raw = intermediary.call("gent_relay_turn_status", {"turn_id": second_id})
    assert len(value["responses"]) == 1 and value["responses"][0]["files"] == files
    assert any(part["type"] == "image" and part["data"] == files[0]["data_base64"] for part in raw["content"])
    intermediary.call("gent_ack", {"message_id": value["responses"][0]["id"]})
    assert target.call("gent_relay_next")[0] is None
    assert intermediary.call("gent_inbox")[0] == []
    assert target.call("gent_inbox")[0] == []
