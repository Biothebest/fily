"""Stable API contract exposed to the Fily desktop frontend."""
from __future__ import annotations

from typing import Any, Dict


def openapi_document(server_url: str = "http://127.0.0.1:8765") -> Dict[str, Any]:
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "Fily Local Desktop API",
            "version": "0.2.0",
            "description": "Local-only API for connected accounts, smart views, and the Fily assistant.",
        },
        "servers": [{"url": server_url}],
        "paths": {
            "/v1/health": {"get": {"summary": "Check local backend health", "responses": {"200": {"description": "Healthy"}}}},
            "/v1/bootstrap": {"get": {"summary": "Load initial desktop workspace state", "parameters": [{"name": "application_limit", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 50, "default": 5}}], "responses": {"200": {"description": "Desktop bootstrap payload"}}}},
            "/v1/accounts": {"get": {"summary": "List connected mail accounts", "responses": {"200": {"description": "Connected accounts"}}}},
            "/v1/job-applications": {"get": {"summary": "List evidence-backed job application cases", "parameters": [{"name": "limit", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 200, "default": 20}}], "responses": {"200": {"description": "Application cases"}}}},
            "/v1/job-applications/{application_id}": {"get": {"summary": "Get one job application case", "parameters": [{"name": "application_id", "in": "path", "required": True, "schema": {"type": "string"}}], "responses": {"200": {"description": "Application case"}, "404": {"description": "Application not found"}}}},
            "/v1/ask": {"post": {"summary": "Ask Fily about indexed email", "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/AskRequest"}}}}, "responses": {"200": {"description": "Evidence-backed assistant response"}, "400": {"description": "Invalid request"}}}},
        },
        "components": {
            "schemas": {
                "AskRequest": {
                    "type": "object",
                    "required": ["question"],
                    "properties": {"question": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}},
                },
                "Account": {
                    "type": "object",
                    "required": ["id", "provider", "status", "indexed_messages"],
                    "properties": {
                        "id": {"type": "string"},
                        "provider": {"type": "string"},
                        "email": {"type": "string", "nullable": True},
                        "status": {"type": "string", "enum": ["connected", "disconnected", "error"]},
                        "indexed_messages": {"type": "integer"},
                    },
                },
                "JobApplication": {
                    "type": "object",
                    "required": ["id", "company", "role", "stage", "application_date", "evidence", "confidence"],
                    "properties": {
                        "id": {"type": "string"},
                        "company": {"type": "string"},
                        "role": {"type": "string"},
                        "stage": {"type": "string", "enum": ["Applied", "Assessment", "Interview", "Offer", "Rejected", "Unknown"]},
                        "application_date": {"type": "string"},
                        "next_action": {"type": "string"},
                        "evidence": {"type": "string"},
                        "evidence_message_id": {"type": "string", "nullable": True},
                        "account": {"type": "string", "nullable": True},
                        "subject": {"type": "string"},
                        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    },
                },
            }
        },
    }


__all__ = ["openapi_document"]
