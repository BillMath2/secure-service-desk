"""Reviewed per-process material and fixed network destinations."""

from service_desk.app_process import BASE as BASE

PORTS = {
    "browser": 19481,
    "agent": 19486,
    "workflow": 19488,
    "proposals": 19484,
    "execution": 19489,
    "collector": 19490,
    "worker": 19491,
    "executor": 19492,
    "delivery": 19493,
}
OUTBOUND = {
    "browser": (19443, 19486, 19487, 19488),
    "agent": (15433, 19443, 19482, 19483, 19484, 19485),
    "workflow": (15433, 19443, 19490),
    "proposals": (15433, 19443),
    "execution": (15433, 19443, 19490),
    "collector": (15433,),
    "worker": (15433, 19490),
    "executor": (19443, 19489),
    "delivery": (15433, 19490),
}
FILES = {
    "browser": BASE
    | {"web.secret", "agent.secret", "publisher.secret", "workflow.secret", "provider.json"},
    "agent": BASE
    | {"gateway.secret", "service.secret", "creator.dsn", "gateway.dsn", "provider.json"},
    "workflow": BASE | {"service.secret", "workflow.dsn", "audit.secret"},
    "proposals": BASE | {"proposals.dsn"},
    "execution": BASE | {"execution.dsn", "audit.secret"},
    "collector": BASE
    | {"collector.dsn", "workflow.secret", "execution.secret", "lifecycle.secret", "reads.secret"},
    "worker": BASE | {"lifecycle.dsn", "audit.secret"},
    "executor": BASE | {"executor.secret"},
    "delivery": BASE | {"delivery.dsn", "audit.secret"},
}
LOGINS = {
    "creator": "read_app",
    "gateway": "read_gateway",
    "workflow": "access_workflow",
    "proposals": "access_proposals",
    "execution": "access_executor",
    "lifecycle": "access_lifecycle",
    "collector": "access_collector",
    "delivery": "access_delivery",
}
WRITERS = {
    "workflow": "workflow",
    "execution": "execution",
    "worker": "lifecycle",
    "delivery": "reads",
}
