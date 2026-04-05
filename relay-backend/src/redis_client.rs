//! Redis connection + leader election.
//! Port of `modules/common/redis_leader_election.go`.

use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;

const REDIS_LEADER_ELECTION_VERSION: u32 = 1;

struct LeaderState {
    is_leader: bool,
    is_ready: bool,
    leader_instance_id: String,
}

pub struct RedisLeaderElection {
    service_name: String,
    instance_id: String,
    start_time: u64,
    initial_delay: u64,
    redis_url: String,
    inner: RwLock<LeaderState>,
}

impl RedisLeaderElection {
    pub fn new(redis_url: &str, service_name: &str, initial_delay: u64) -> Self {
        let instance_id = uuid::Uuid::new_v4().to_string();
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos() as u64;

        log::debug!("redis leader election instance id: {}", instance_id);

        RedisLeaderElection {
            service_name: service_name.to_string(),
            instance_id,
            start_time,
            initial_delay,
            redis_url: redis_url.to_string(),
            inner: RwLock::new(LeaderState {
                is_leader: false,
                is_ready: false,
                leader_instance_id: String::new(),
            }),
        }
    }

    pub async fn update(&self) {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_secs();
        let period = seconds / 3;

        // Connect to Redis
        let client = match redis::Client::open(format!("redis://{}", self.redis_url)) {
            Ok(c) => c,
            Err(e) => {
                log::error!("redis connect error: {}", e);
                return;
            }
        };
        let mut con = match client.get_multiplexed_async_connection().await {
            Ok(c) => c,
            Err(e) => {
                log::error!("redis connection error: {}", e);
                return;
            }
        };

        // Write our instance entry (simple format: "instance_id|start_time|update_time")
        let key = format!(
            "{}-instance-{}-{}",
            self.service_name, REDIS_LEADER_ELECTION_VERSION, period
        );
        let value = format!("{}|{}|{}", self.instance_id, self.start_time, seconds);

        let _: Result<(), _> = redis::cmd("HSET")
            .arg(&key)
            .arg(&self.instance_id)
            .arg(&value)
            .query_async(&mut con)
            .await;

        // Check if initial delay has passed
        let elapsed = seconds.saturating_sub(self.start_time / 1_000_000_000);
        if elapsed < self.initial_delay {
            log::debug!(
                "waiting for leader election initial delay ({})",
                self.initial_delay
            );
            return;
        }

        // Get all instance entries
        let key_a = format!(
            "{}-instance-{}-{}",
            self.service_name, REDIS_LEADER_ELECTION_VERSION, period
        );
        let key_b = format!(
            "{}-instance-{}-{}",
            self.service_name,
            REDIS_LEADER_ELECTION_VERSION,
            period - 1
        );

        let instances_a: std::collections::HashMap<String, String> = redis::cmd("HGETALL")
            .arg(&key_a)
            .query_async(&mut con)
            .await
            .unwrap_or_default();

        let instances_b: std::collections::HashMap<String, String> = redis::cmd("HGETALL")
            .arg(&key_b)
            .query_async(&mut con)
            .await
            .unwrap_or_default();

        // Merge and parse
        let mut instance_map = instances_b;
        for (k, v) in instances_a {
            instance_map.insert(k, v);
        }

        let mut entries: Vec<(String, u64)> = Vec::new();
        for v in instance_map.values() {
            let parts: Vec<&str> = v.split('|').collect();
            if parts.len() >= 2 {
                if let Ok(start) = parts[1].parse::<u64>() {
                    entries.push((parts[0].to_string(), start));
                }
            }
        }

        if entries.is_empty() {
            log::debug!("no instance entries");
            return;
        }

        // Sort by start_time (earliest first), tie-break by instance_id
        entries.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));

        let leader_id = entries[0].0.clone();

        let mut state = self.inner.write().expect("leader state lock poisoned");
        let prev = state.is_leader;
        let curr = leader_id == self.instance_id;
        state.is_leader = curr;
        state.is_ready = true;
        state.leader_instance_id = leader_id;

        if !prev && curr {
            log::info!("we became the leader");
        } else if prev && !curr {
            log::info!("we are no longer the leader");
        }
    }

    pub async fn store(&self, name: &str, data: &[u8]) {
        let key = format!(
            "{}-instance-data-{}-{}-{}",
            self.service_name, REDIS_LEADER_ELECTION_VERSION, self.instance_id, name
        );

        let client = match redis::Client::open(format!("redis://{}", self.redis_url)) {
            Ok(c) => c,
            Err(e) => {
                log::error!("redis store connect error: {}", e);
                return;
            }
        };
        let mut con = match client.get_multiplexed_async_connection().await {
            Ok(c) => c,
            Err(e) => {
                log::error!("redis store connection error: {}", e);
                return;
            }
        };

        let _: Result<(), _> = redis::cmd("SET")
            .arg(&key)
            .arg(data)
            .query_async(&mut con)
            .await;
    }

    pub async fn load(&self, name: &str) -> Option<Vec<u8>> {
        let leader_id = {
            let state = self.inner.read().expect("leader state lock poisoned");
            state.leader_instance_id.clone()
        };

        if leader_id.is_empty() {
            return None;
        }

        let key = format!(
            "{}-instance-data-{}-{}-{}",
            self.service_name, REDIS_LEADER_ELECTION_VERSION, leader_id, name
        );

        let client = redis::Client::open(format!("redis://{}", self.redis_url)).ok()?;
        let mut con = client.get_multiplexed_async_connection().await.ok()?;

        let value: Option<Vec<u8>> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut con)
            .await
            .ok()?;

        value
    }

    #[allow(dead_code)]
    pub fn is_leader(&self) -> bool {
        self.inner
            .read()
            .expect("leader state lock poisoned")
            .is_leader
    }

    pub fn is_ready(&self) -> bool {
        self.inner
            .read()
            .expect("leader state lock poisoned")
            .is_ready
    }
}
