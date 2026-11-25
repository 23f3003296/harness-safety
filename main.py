
from fastapi import FastAPI, Request, Body
from fastapi.responses import JSONResponse

app = FastAPI()


# --------------------------------------------------
# 1. Helpers
# --------------------------------------------------

def get_latest_user_message(case):
    messages = case.get("messages", [])

    user_messages = [
        m.get("content", "")
        for m in messages
        if m.get("role") == "user"
    ]

    return user_messages[-1] if user_messages else ""


def text_from_case(case):
    parts = [get_latest_user_message(case)]

    for item in case.get("memory", []):
        parts.append(str(item))

    for item in case.get("repositoryInstructions", []):
        parts.append(str(item))

    return " ".join(parts).lower()


def has_security_context(case):
    text = text_from_case(case)

    security_terms = [
        "exploit", "vulnerability", "security test",
        "penetration test", "pentest", "payload",
        "vulnerability discovery"
    ]

    return any(term in text for term in security_terms)


def has_untrusted_redirect(case):
    sources = (
        case.get("memory", [])
        + case.get("repositoryInstructions", [])
        + case.get("toolResults", [])
    )

    suspicious_terms = [
        "ignore previous instructions",
        "ignore the policy",
        "override the policy",
        "bypass safety",
        "reveal credentials",
        "exfiltrate"
    ]

    for item in sources:
        text = str(item).lower()

        if any(term in text for term in suspicious_terms):
            return True

    return False


def is_forbidden_request(case):
    text = text_from_case(case)

    forbidden_terms = [
        "steal credentials",
        "steal password",
        "exfiltrate private data",
        "commit fraud",
        "harass",
        "destructive malware",
        "cause physical harm"
    ]

    return any(term in text for term in forbidden_terms)


# --------------------------------------------------
# 2. Request decision
# --------------------------------------------------

def classify_request(case):

    if is_forbidden_request(case):
        return "block"

    text = text_from_case(case)

    security_terms = [
        "exploit", "vulnerability",
        "penetration test", "pentest"
    ]

    if any(term in text for term in security_terms):
        return "review" if unclear_security_scope(case) else "allow"

    return "allow"


def unclear_security_scope(case):

    resolved = (
        case.get("proposedTool", {})
        .get("resolved", {})
    )

    if not resolved:
        return True

    target = resolved.get("target")

    if not target:
        return True

    if resolved.get("environment") == "unknown":
        return True

    return False


# --------------------------------------------------
# 3. Tool decision
# --------------------------------------------------

def classify_tool(case, request_decision):

    tool = case.get("proposedTool")

    if not tool:
        return "none"

    if request_decision == "block":
        return "block"

    resolved = tool.get("resolved", {})
    operation = resolved.get("operation", "")
    target = resolved.get("target")
    environment = resolved.get("environment", "")

    if not resolved or not target or environment == "unknown":
        return "review"

    if operation in ["read", "inspect"]:
        return "allow"

    # Safe disposable-fixture deletion
    if operation == "delete":

        env = case.get("environment", {})
        isolation = env.get("isolation", {})

        if (
            environment == "container"
            and resolved.get("disposable") is True
            and isolation.get("verified") is True
            and isolation.get("hostMounts") == []
            and isolation.get("credentials") is False
            and isolation.get("externalNetwork") is False
        ):
            return "allow"

        return "review"

    # Production mutations
    if environment == "production":

        preflight_ok = False
        rollback_ok = bool(case.get("rollbackPlan"))

        for result in case.get("toolResults", []):
            if (
                isinstance(result, dict)
                and result.get("preflight") == "success"
            ):
                preflight_ok = True

        if preflight_ok and rollback_ok:
            return "review"

        return "review"

    # Consequential actions need exact authorization
    if operation in [
        "send", "transfer", "push",
        "deploy", "modify", "change"
    ]:
        return "review"

    return "review"


# --------------------------------------------------
# 4. Model routing
# --------------------------------------------------

def classify_route(case, request_decision):

    if request_decision == "block":
        return "none"

    if has_security_context(case):
        return "restricted"

    return "primary"


# --------------------------------------------------
# 5. Session trajectory
# --------------------------------------------------

def classify_trajectory(
    case,
    request_decision,
    tool_decision
):

    if request_decision == "block":
        return "intervene"

    if tool_decision == "block":
        return "intervene"

    if (
        request_decision == "review"
        or tool_decision == "review"
        or has_security_context(case)
        and unclear_security_scope(case)
        or has_untrusted_redirect(case)
    ):
        return "watch"

    return "normal"


# --------------------------------------------------
# 6. Process each independent case
# --------------------------------------------------

def process_case(case):

    request_decision = classify_request(case)

    tool_decision = classify_tool(
        case, request_decision
    )

    route = classify_route(
        case, request_decision
    )

    trajectory = classify_trajectory(
        case,
        request_decision,
        tool_decision
    )

    return {
        "caseId": case.get("caseId"),
        "requestDecision": request_decision,
        "toolDecision": tool_decision,
        "route": route,
        "trajectory": trajectory
    }


# --------------------------------------------------
# 7. HTTPS POST endpoint
# --------------------------------------------------

@app.post("/")
async def classify_batch(data: dict = Body(...)):

    cases = data.get("cases", [])

    results = [
        process_case(case)
        for case in cases
    ]

    return {
        "profile": data.get("profile"),
        "batchId": data.get("batchId"),
        "results": results
    }


@app.get("/")
async def health_check():

    return {
        "status": "running",
        "service": "harness-safety-classifier"
    }
