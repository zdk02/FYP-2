"""
Notifications & Subscription Abuse (Pro) — MCP-novel.

MCP defines server-pushed channels:
  - `notifications/*` (e.g. notifications/resources/list_changed,
    notifications/resources/updated, notifications/tools/list_changed,
    notifications/prompts/list_changed, notifications/message,
    notifications/cancelled)
  - `resources/subscribe` to subscribe to a specific resource URI

Attack surface:

  1. UNAUTHENTICATED SUBSCRIBE — server allows resources/subscribe
     from unauth callers, potentially leaking change events.
  2. UNBOUNDED SUBSCRIBE — server accepts subscriptions to any number
     of resources (or wildcards) without a per-client cap, enabling
     subscription flooding for memory exhaustion.
  3. NON-EXISTENT RESOURCE SUBSCRIBE — server accepts subscriptions
     to URIs that don't exist (no validation), potentially used as a
     storage primitive.
  4. MALFORMED NOTIFICATION HANDLING — server crashes / leaks on
     receiving malformed `notifications/*` from a client (the spec
     allows clients to send some notifications too, e.g. cancelled,
     initialized).

Confidence: confirmed for 4-tier acceptance / leakage; high for sloppy
validation; medium for absent rate-limiting.
"""

import time as _time


_FLOOD_TARGETS_DEFAULT = 50


def execute(target, params, context):
    rb = evidence.ReportBuilder(
        attack_id=context.get("attack_id", "notifications_subscription_abuse"),
        target=target,
    )
    timeout = int(params.get("timeout", 20))
    flood_count = int(params.get("flood_count", _FLOOD_TARGETS_DEFAULT))
    test_unauth = bool(params.get("test_unauth", True))
    test_malformed = bool(params.get("test_malformed", True))
    test_unknown_uri = bool(params.get("test_unknown_uri", True))
    transport_override = params.get("transport_override") or None
    protocol_version = params.get("protocol_version") or None

    mcp = mcp_client.MCPClient.from_target(
        target, timeout=timeout,
        protocol_version=protocol_version,
        force_transport=transport_override,
    )
    try:
        disc = mcp.discover()
        if not disc["initialized"]:
            rb.error(f"MCP initialize failed: {disc.get('errors')}")
            return rb.finalize(success=False)

        capabilities = disc.get("capabilities") or {}
        resources_cap = capabilities.get("resources") or {}
        advertises_subscribe = bool(resources_cap.get("subscribe"))
        rb.info(f"Server resources.subscribe capability: {advertises_subscribe}")

        # ------------------------------------------------------------------
        # Vector 1: subscribe to non-existent URI
        # ------------------------------------------------------------------
        if test_unknown_uri:
            unknown_uri = "minerva://nonexistent/" + str(int(_time.time()))
            resp = mcp_client.call(
                target, "resources/subscribe",
                {"uri": unknown_uri}, timeout=timeout,
            )
            rb.add_evidence(evidence.ev_mcp_call(resp, note="subscribe non-existent"))
            body = resp.get("response") or {}
            if "error" not in body:
                rb.add_finding(evidence.Finding(
                    attack_id=context.get("attack_id", "notifications_subscription_abuse"),
                    title="resources/subscribe accepts non-existent URIs without validation",
                    category="notifications_subscription_validation",
                    severity="medium", confidence="high",
                    parameter="uri",
                    payload=unknown_uri,
                    description=(
                        "Server accepted a subscription to a URI that does not "
                        "appear in resources/list. This indicates missing input "
                        "validation; subscribers can be tricked into thinking a "
                        "resource exists, and an attacker can use the subscription "
                        "table as cheap storage / abuse the server's bookkeeping."
                    ),
                    impact=(
                        "Abusable as a confused-deputy primitive and as memory "
                        "amplification when combined with flood subscribe."
                    ),
                    remediation=(
                        "Reject resources/subscribe for URIs not present in the "
                        "current resources/list."
                    ),
                    cwe="CWE-20",
                ))

        # ------------------------------------------------------------------
        # Vector 2: subscription flooding
        # ------------------------------------------------------------------
        accepted = 0
        latencies = []
        for i in range(flood_count):
            uri = f"minerva://flood/{i}/{int(_time.time())}"
            t0 = _time.time()
            resp = mcp_client.call(
                target, "resources/subscribe",
                {"uri": uri}, timeout=timeout,
            )
            latencies.append((_time.time() - t0) * 1000)
            body = resp.get("response") or {}
            if "error" not in body:
                accepted += 1
            else:
                err = body.get("error") or {}
                msg = (err.get("message") or "").lower()
                if "limit" in msg or "rate" in msg or "too many" in msg:
                    rb.info(f"  rate-limit kicked in at flood #{i}: {err}")
                    break

        if accepted >= flood_count:
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "notifications_subscription_abuse"),
                title=f"resources/subscribe accepts unlimited subscriptions ({accepted} consecutive accepts)",
                category="notifications_subscribe_flood",
                severity="medium", confidence="confirmed",
                description=(
                    f"Server accepted {accepted} consecutive subscriptions to "
                    f"distinct generated URIs without rejecting or rate-limiting. "
                    f"An attacker can exhaust server memory / handler tables by "
                    f"subscribing to a large number of resources."
                ),
                impact="Memory-exhaustion DoS via subscription flooding.",
                remediation=(
                    "Apply a per-client subscription cap (e.g. 256) and a "
                    "rate-limit (e.g. 10/sec) on resources/subscribe."
                ),
                cwe="CWE-770",
                references=["https://cwe.mitre.org/data/definitions/770.html"],
            ))
        elif accepted > 0:
            rb.info(f"  partial flood: {accepted}/{flood_count} accepted before rate-limit")

        # ------------------------------------------------------------------
        # Vector 3: malformed notifications (client → server)
        # ------------------------------------------------------------------
        if test_malformed:
            malformed_payloads = [
                # cancelled with no requestId
                ("notifications/cancelled", {}),
                # cancelled with bogus requestId type
                ("notifications/cancelled", {"requestId": {"x": 1}}),
                # initialized with extra fields
                ("notifications/initialized", {"surprise": "X" * 4096}),
                # unknown notification with wild params
                ("notifications/minerva/probe", {"a": "b" * 8192}),
                # malformed message notification
                ("notifications/message", {"level": "fake_level",
                                           "data": "X" * 8192}),
            ]
            for method, params2 in malformed_payloads:
                t0 = _time.time()
                # Use a notification call (no id) — wrap in mcp_client.call
                # which still issues a request; servers should ignore
                # unknown notifications gracefully.
                try:
                    resp = mcp_client.call(
                        target, method, params2, timeout=timeout,
                    )
                except Exception as e:
                    rb.warn(f"transport raised on malformed {method}: {e}")
                    continue
                lat = (_time.time() - t0) * 1000
                body = resp.get("response") or {}
                err = body.get("error") or {}
                err_text = (str(err.get("message") or "") + " "
                            + str(err.get("data") or ""))[:1000]
                # Indicators that the server crashed / leaked
                if any(s in err_text for s in
                       ("Traceback", "NullPointerException", "panic:",
                        "AttributeError", "IndexError", "KeyError", "stack ")):
                    f = evidence.Finding(
                        attack_id=context.get("attack_id", "notifications_subscription_abuse"),
                        title=f"Malformed {method} reveals stack trace / runtime error",
                        category="notifications_malformed_handling",
                        severity="high", confidence="confirmed",
                        parameter="params",
                        payload=method,
                        description=(
                            f"Sending a malformed {method} notification "
                            f"produced a response that includes a stack trace "
                            f"or runtime error indicator. The server is not "
                            f"handling notifications defensively."
                        ),
                        impact="Information disclosure + likely DoS surface.",
                        remediation=(
                            "Wrap notification handlers in try/except. Validate "
                            "params against a schema; reject silently on mismatch."
                        ),
                        cwe="CWE-209",
                    )
                    f.add_evidence(evidence.ev_mcp_call(resp,
                                   note=f"malformed {method}"))
                    rb.add_finding(f)

        # ------------------------------------------------------------------
        # Vector 4: subscribe acceptance without capability advertisement
        # ------------------------------------------------------------------
        if not advertises_subscribe and accepted > 0:
            rb.add_finding(evidence.Finding(
                attack_id=context.get("attack_id", "notifications_subscription_abuse"),
                title="resources/subscribe accepted despite resources.subscribe NOT advertised",
                category="notifications_subscribe_undeclared",
                severity="medium", confidence="high",
                description=(
                    "Server's initialize/capabilities did not declare "
                    "resources.subscribe, but resources/subscribe requests "
                    "were honoured. Indicates undocumented behaviour and "
                    "implementation/contract drift."
                ),
                impact="Behaviour available to attackers but invisible to documentation/clients.",
                remediation="Either advertise the capability or reject subscribe requests.",
                cwe="CWE-440",
            ))

        return rb.finalize()
    finally:
        try:
            mcp.close()
        except Exception:
            pass
