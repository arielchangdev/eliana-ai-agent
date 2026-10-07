"""ELIANA_SCHEMA — eliana.yaml 的 JSON Schema（Draft 7）。

供 ConfigManager.validate_schema 使用。敏感值（token/密碼）不在 schema 中要求，
因為它們透過 ELIANA_ 環境變數於執行期注入。
"""
from __future__ import annotations

ELIANA_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "app": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "standalone": {"type": "boolean"},
                "skip_validation": {"type": "boolean"},
                "host": {"type": "string"},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
            },
            "required": ["name", "host", "port"],
        },
        "hosts": {
            "type": "object",
            "properties": {
                "weapon_host": {
                    "type": "object",
                    "properties": {
                        "hostname": {"type": "string"},
                        "ssh_user": {"type": "string"},
                        "ssh_key_path": {"type": "string"},
                        "ssh_port": {"type": "integer", "minimum": 1, "maximum": 65535},
                    },
                    "required": ["hostname", "ssh_user", "ssh_key_path"],
                },
            },
            "required": ["weapon_host"],
        },
        "ollama": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string"},
                "model": {"type": "string"},
                "timeout_seconds": {"type": "number", "minimum": 0},
            },
            "required": ["base_url"],
        },
        "wallet": {
            "type": "object",
            "properties": {
                "electrum_rpc_url": {"type": "string"},
                "rpc_user": {"type": "string"},
                "network": {"type": "string", "enum": ["mainnet", "testnet", "regtest"]},
            },
            "required": ["electrum_rpc_url"],
        },
        "chromadb": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "collection": {"type": "string"},
            },
            "required": ["host", "port"],
        },
        "telegram": {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean"},
                "chat_id": {"type": "string"},
                "api_base": {"type": "string"},
            },
            "required": ["enabled"],
        },
        "bounty": {
            "type": "object",
            "properties": {
                "crawl_interval_minutes": {"type": "integer", "minimum": 1},
                "require_manual_authorization": {"type": "boolean"},
                "allowed_platforms": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            "required": ["require_manual_authorization"],
        },
        "personality": {
            "type": "object",
            "properties": {
                "active_profile": {"type": "string"},
                "evolution_enabled": {"type": "boolean"},
                "max_single_change_pct": {"type": "number", "minimum": 0, "maximum": 100},
                "max_cumulative_change_pct": {"type": "number", "minimum": 0, "maximum": 100},
            },
        },
        "event_bus": {
            "type": "object",
            "properties": {
                "retry_delay_seconds": {"type": "number", "minimum": 0},
                "max_retries": {"type": "integer", "minimum": 0},
            },
        },
        "health": {
            "type": "object",
            "properties": {
                "cache_ttl_seconds": {"type": "number", "minimum": 0},
                "check_timeout_seconds": {"type": "number", "minimum": 0},
            },
        },
    },
    "required": ["app", "hosts", "ollama", "wallet", "chromadb", "telegram", "bounty"],
}
