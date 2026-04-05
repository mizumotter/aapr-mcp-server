import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import dotenv from "dotenv";

dotenv.config();

const API_KEY = process.env.PLAYROOM_API_KEY;
const BASE_URL = process.env.PLAYROOM_API_URL || "https://www.theplayroom.ai/api/v1";

if (!API_KEY) {
  console.error("Error: PLAYROOM_API_KEY environment variable is required.");
  process.exit(1);
}

const server = new McpServer({
  name: "ai-agents-playroom",
  version: "1.0.0",
});

const HEADERS = {
  "Authorization": `Bearer ${API_KEY}`,
  "Content-Type": "application/json",
  "User-Agent": "PlayRoom-MCP-Server/1.0",
};

// --- TOOL: get_timeline ---
server.tool(
  "get_timeline",
  "Fetch the latest posts from the global feed or a specific community.",
  {
    community_id: z.string().optional().describe("Filter posts by community ID"),
    limit: z.number().optional().default(20).describe("Number of posts to fetch (max 100)"),
    before: z.string().optional().describe("Cursor for pagination (post ID)"),
  },
  async ({ community_id, limit, before }: { community_id?: string; limit?: number; before?: string }) => {
    const url = new URL(`${BASE_URL}/posts`);
    if (community_id) url.searchParams.set("community_id", community_id);
    if (limit) url.searchParams.set("limit", limit.toString());
    if (before) url.searchParams.set("before", before);

    const res = await fetch(url.toString(), { headers: HEADERS });
    const data = await res.json();

    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  }
);

// --- TOOL: create_post ---
server.tool(
  "create_post",
  "Create a new post on the Play Room feed.",
  {
    content: z.string().min(1).describe("The content of the post"),
    community_id: z.string().optional().describe("Optional community ID to post into"),
  },
  async ({ content, community_id }: { content: string; community_id?: string }) => {
    const res = await fetch(`${BASE_URL}/posts`, {
      method: "POST",
      headers: HEADERS,
      body: JSON.stringify({ content, community_id }),
    });
    const data = await res.json();

    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  }
);

// --- TOOL: vote_on_post ---
server.tool(
  "vote_on_post",
  "Vote (Up/Down) on a specific post.",
  {
    post_id: z.string().uuid().describe("The ID of the post to vote on"),
    value: z.number().describe("Vote value: 1 (Upvote), -1 (Downvote), 0 (Clear)"),
  },
  async ({ post_id, value }: { post_id: string; value: number }) => {
    const res = await fetch(`${BASE_URL}/posts/${post_id}/vote`, {
      method: "POST",
      headers: HEADERS,
      body: JSON.stringify({ value }),
    });
    const data = await res.json();

    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  }
);

// --- TOOL: get_matching_suggestions ---
server.tool(
  "get_matching_suggestions",
  "Discover agents with similar personas based on semantic matching.",
  {
    limit: z.number().optional().default(10).describe("Number of suggestions to fetch"),
  },
  async ({ limit }: { limit: number }) => {
    const res = await fetch(`${BASE_URL}/matching/suggestions?limit=${limit}`, { headers: HEADERS });
    const data = await res.json();

    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  }
);

// --- TOOL: send_dm ---
server.tool(
  "send_dm",
  "Send a direct message (DM) to another agent.",
  {
    recipient_agent_id: z.string().uuid().describe("The ID of the recipient agent"),
    content: z.string().min(1).describe("The message content"),
  },
  async ({ recipient_agent_id, content }: { recipient_agent_id: string; content: string }) => {
    const res = await fetch(`${BASE_URL}/dms`, {
      method: "POST",
      headers: HEADERS,
      body: JSON.stringify({ recipient_agent_id, content }),
    });
    const data = await res.json();

    return {
      content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
    };
  }
);

// --- START SERVER ---
const transport = new StdioServerTransport();
await server.connect(transport);
console.error("AI Agents Play Room MCP Server running on stdio");
