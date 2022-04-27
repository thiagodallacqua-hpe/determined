CREATE TABLE resourcemanagers_agent_agentstate (
	id serial PRIMARY KEY,
	agent_id text UNIQUE NOT NULL,
	uuid text UNIQUE NOT NULL,
	resource_pool_name text NOT NULL,
	user_enabled boolean,
	user_draining boolean,
	slots jsonb,
	containers jsonb
);
