"""
TEZCATL — Graph-Native Security Containment Agent (FalkorDB)
Author: Aadrit555 (https://github.com/Aadrit555/we-make-devs-GRAPH_HACKS)
"""

import sys
import json
from typing import Dict, Any, List, Optional, Union
from config import settings
from graph_client import FalkorGraphClient, DEFAULT_HOST, DEFAULT_PORT, DEFAULT_GRAPH, DEFAULT_MIRROR_GRAPH
from models import (
    JsonRpcRequest,
    JsonRpcResponse,
    JsonRpcError,
    McpToolDefinition,
    McpCallToolRequest,
)

# Standard MCP Tool Definitions
MCP_TOOLS: List[McpToolDefinition] = [
    McpToolDefinition(
        name="find_attack_paths",
        description="Traverse active directed ATTACK_STEP relationships (*1..8) to identify lateral breach trajectories.",
        inputSchema={
            "type": "object",
            "properties": {
                "source_id": {"type": "string", "description": "Compromised ingress entity ID"},
                "target_id": {"type": "string", "description": "Crown-jewel target entity ID (default: signing_key)"},
                "max_hops": {"type": "integer", "description": "Maximum traversal depth (1-8)", "default": 8},
            },
            "required": ["source_id"],
        },
    ),
    McpToolDefinition(
        name="rank_betweenness_bottlenecks",
        description="Execute FalkorDB native algo.betweenness procedure to rank structural graph bottlenecks.",
        inputSchema={
            "type": "object",
            "properties": {},
        },
    ),
    McpToolDefinition(
        name="compute_service_blast_radius",
        description="Reverse-traverse downstream DEPENDS_ON service trees to dynamically calculate operational disruption costs.",
        inputSchema={
            "type": "object",
            "properties": {
                "path_node_ids": {"type": "array", "items": {"type": "string"}, "description": "Candidate node IDs on attack paths"},
                "source_id": {"type": "string", "description": "Compromised source ID (excluded from cut candidates)"},
            },
            "required": ["path_node_ids", "source_id"],
        },
    ),
    McpToolDefinition(
        name="simulate_mirror_containment",
        description="Clone prod_graph to tezcatl_mirror, sever candidate entities, and verify remaining_paths == 0 in sandbox.",
        inputSchema={
            "type": "object",
            "properties": {
                "blocked_ids": {"type": "array", "items": {"type": "string"}, "description": "Node IDs to sever in sandbox"},
                "source_id": {"type": "string", "description": "Compromised source ID"},
                "target_id": {"type": "string", "description": "Crown jewel target ID"},
                "max_hops": {"type": "integer", "description": "Hop bound", "default": 8},
                "mirror_graph_name": {"type": "string", "description": "Isolated sandbox graph name"},
            },
            "required": ["blocked_ids"],
        },
    ),
    McpToolDefinition(
        name="apply_containment_action",
        description="Commit authorized containment mutation to production graph (SET status = 'disabled').",
        inputSchema={
            "type": "object",
            "properties": {
                "blocked_ids": {"type": "array", "items": {"type": "string"}, "description": "Entities to sever in production"},
            },
            "required": ["blocked_ids"],
        },
    ),
    McpToolDefinition(
        name="compute_graph_state_hash",
        description="Compute canonical SHA-256 fingerprint of current FalkorDB graph state.",
        inputSchema={
            "type": "object",
            "properties": {
                "graph_name": {"type": "string", "description": "Target graph name"},
            },
        },
    ),
]


class McpServer:
    """First-party JSON-RPC 2.0 Model Context Protocol tool server for TEZCATL."""

    def __init__(self, client: Optional[FalkorGraphClient] = None):
        self.client = client or FalkorGraphClient(
            host=settings.falkordb_host,
            port=settings.falkordb_port,
            graph_name=settings.falkordb_graph,
        )

    def list_tools(self) -> List[Dict[str, Any]]:
        """Return standardized MCP tool specifications."""
        return [tool.model_dump() for tool in MCP_TOOLS]

    def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Dispatch tool execution directly to FalkorDB client."""
        if tool_name == "find_attack_paths":
            source_id = arguments.get("source_id", settings.tezcatl_source_id)
            target_id = arguments.get("target_id", settings.tezcatl_target_id)
            max_hops = int(arguments.get("max_hops", 8))
            paths = self.client.discover_attack_paths(source_id=source_id, target_id=target_id, max_hops=max_hops)
            return [p.model_dump() for p in paths]

        elif tool_name == "rank_betweenness_bottlenecks":
            scores = self.client.get_betweenness_centrality()
            return [s.model_dump() for s in scores]

        elif tool_name == "compute_service_blast_radius":
            path_nodes = arguments.get("path_node_ids", [])
            source_id = arguments.get("source_id", settings.tezcatl_source_id)
            candidates = self.client.get_cut_candidates(path_node_ids=path_nodes, source_id=source_id)
            return [c.model_dump() for c in candidates]

        elif tool_name == "simulate_mirror_containment":
            blocked_ids = arguments.get("blocked_ids", [])
            source_id = arguments.get("source_id", settings.tezcatl_source_id)
            target_id = arguments.get("target_id", settings.tezcatl_target_id)
            max_hops = int(arguments.get("max_hops", 8))
            mirror_name = arguments.get("mirror_graph_name", settings.falkordb_mirror_graph)
            sim = self.client.simulate_mirror_containment(
                blocked_ids=blocked_ids,
                source_id=source_id,
                target_id=target_id,
                max_hops=max_hops,
                mirror_graph_name=mirror_name,
            )
            return {
                "mirror_graph_name": sim["mirror_graph_name"],
                "blocked_ids": sim["blocked_ids"],
                "mutation_result": sim["mutation_result"].model_dump() if hasattr(sim["mutation_result"], "model_dump") else sim["mutation_result"],
                "mirror_paths": [p.model_dump() for p in sim.get("mirror_paths", [])],
                "mirror_remaining_count": sim["mirror_remaining_count"],
                "mirror_centrality": [c.model_dump() for c in sim.get("mirror_centrality", [])],
                "simulation_latency_ms": sim["simulation_latency_ms"],
                "verified_contained": sim["verified_contained"],
            }

        elif tool_name == "apply_containment_action":
            blocked_ids = arguments.get("blocked_ids", [])
            mut = self.client.apply_containment_action(blocked_ids=blocked_ids)
            return mut.model_dump()

        elif tool_name == "compute_graph_state_hash":
            return self.client.compute_graph_state_hash()

        else:
            raise ValueError(f"Unknown MCP tool: '{tool_name}'")

    def handle_request(self, raw_request: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Process a JSON-RPC 2.0 request and return a JSON-RPC 2.0 response dictionary."""
        if isinstance(raw_request, str):
            try:
                payload = json.loads(raw_request)
            except json.JSONDecodeError as exc:
                return JsonRpcResponse(
                    id=None,
                    error=JsonRpcError(code=-32700, message=f"Parse error: {exc}"),
                ).model_dump()
        else:
            payload = raw_request

        if not isinstance(payload, dict):
            return JsonRpcResponse(
                id=None,
                error=JsonRpcError(code=-32600, message="Invalid Request: payload must be a JSON object"),
            ).model_dump()

        req_id = payload.get("id")
        method = payload.get("method")
        params = payload.get("params", {})

        if not method or not isinstance(method, str):
            return JsonRpcResponse(
                id=req_id,
                error=JsonRpcError(code=-32600, message="Invalid Request: method missing or not a string"),
            ).model_dump()

        try:
            if method in ("tools/list", "mcp.list_tools"):
                tools = self.list_tools()
                return JsonRpcResponse(id=req_id, result={"tools": tools}).model_dump()

            elif method in ("tools/call", "mcp.call_tool"):
                tool_name = params.get("name")
                arguments = params.get("arguments", {})
                if not tool_name:
                    return JsonRpcResponse(
                        id=req_id,
                        error=JsonRpcError(code=-32602, message="Invalid params: tool name required"),
                    ).model_dump()
                tool_result = self.call_tool(tool_name, arguments)
                return JsonRpcResponse(id=req_id, result={"content": tool_result}).model_dump()

            elif any(tool.name == method for tool in MCP_TOOLS):
                tool_result = self.call_tool(method, params)
                return JsonRpcResponse(id=req_id, result=tool_result).model_dump()

            else:
                return JsonRpcResponse(
                    id=req_id,
                    error=JsonRpcError(code=-32601, message=f"Method not found: '{method}'"),
                ).model_dump()

        except Exception as exc:
            return JsonRpcResponse(
                id=req_id,
                error=JsonRpcError(code=-32603, message=f"Internal error: {exc}"),
            ).model_dump()


def run_stdio_server():
    """Run JSON-RPC 2.0 MCP server over stdio for external MCP clients."""
    server = McpServer()
    for line in sys.stdin:
        line_clean = line.strip()
        if not line_clean:
            continue
        response = server.handle_request(line_clean)
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    run_stdio_server()
