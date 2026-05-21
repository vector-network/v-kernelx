use crate::VectorEvent;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagConflict {
    pub event_hash: String,
    pub reason: String,
}

fn event_index(events: &[VectorEvent]) -> Result<BTreeMap<String, usize>, String> {
    let mut index = BTreeMap::new();

    for (i, event) in events.iter().enumerate() {
        if event.event_hash.is_empty() {
            return Err(format!("event {} has empty event_hash", event.event_id));
        }

        if index.insert(event.event_hash.clone(), i).is_some() {
            return Err(format!(
                "duplicate event_hash detected: {}",
                event.event_hash
            ));
        }
    }

    Ok(index)
}

fn sort_key(event: &VectorEvent) -> (u64, u64, String, String) {
    (
        event.logical_clock,
        event.timestamp,
        event.event_hash.clone(),
        event.event_id.clone(),
    )
}

pub fn detect_conflicts(events: &[VectorEvent]) -> Vec<DagConflict> {
    let mut conflicts = Vec::new();

    let index = match event_index(events) {
        Ok(v) => v,
        Err(err) => {
            conflicts.push(DagConflict {
                event_hash: String::new(),
                reason: err,
            });
            return conflicts;
        }
    };

    for event in events {
        let mut seen_parents = BTreeSet::new();

        if event.parent_hashes.iter().any(|p| p == &event.event_hash) {
            conflicts.push(DagConflict {
                event_hash: event.event_hash.clone(),
                reason: "self-parent cycle detected".to_string(),
            });
        }

        for parent in &event.parent_hashes {
            if !seen_parents.insert(parent.clone()) {
                conflicts.push(DagConflict {
                    event_hash: event.event_hash.clone(),
                    reason: format!("duplicate parent hash in event: {parent}"),
                });
            }

            if !index.contains_key(parent) {
                conflicts.push(DagConflict {
                    event_hash: event.event_hash.clone(),
                    reason: format!("missing parent event: {parent}"),
                });
            }
        }
    }

    conflicts
}

fn validate_region_admissibility(parent: &VectorEvent, child: &VectorEvent) -> Result<(), String> {
    if parent.region_id != child.region_id {
        return Err(format!(
            "region inadmissible: parent region {} != child region {}",
            parent.region_id, child.region_id
        ));
    }
    Ok(())
}

pub fn validate_dag(events: &[VectorEvent]) -> Result<(), String> {
    let index = event_index(events)?;

    let mut graph = BTreeMap::<String, Vec<String>>::new();
    let mut indegree = BTreeMap::<String, usize>::new();

    for event in events {
        indegree.entry(event.event_hash.clone()).or_insert(0);
        graph.entry(event.event_hash.clone()).or_default();
    }

    for event in events {
        let mut seen_parents = BTreeSet::new();

        for parent_hash in &event.parent_hashes {
            if !seen_parents.insert(parent_hash.clone()) {
                return Err(format!(
                    "duplicate parent hash in event: {}",
                    event.event_hash
                ));
            }

            let parent_index = *index
                .get(parent_hash)
                .ok_or_else(|| format!("missing parent event: {parent_hash}"))?;

            let parent = &events[parent_index];
            validate_region_admissibility(parent, event)?;

            graph
                .entry(parent_hash.clone())
                .or_default()
                .push(event.event_hash.clone());

            *indegree.entry(event.event_hash.clone()).or_insert(0) += 1;
        }
    }

    let mut queue = VecDeque::new();
    for (hash, deg) in &indegree {
        if *deg == 0 {
            queue.push_back(hash.clone());
        }
    }

    let mut visited = 0_usize;
    while let Some(node) = queue.pop_front() {
        visited += 1;

        if let Some(children) = graph.get(&node) {
            let mut sorted_children = children.clone();
            sorted_children.sort_by(|a, b| {
                let ia = index.get(a).copied().unwrap();
                let ib = index.get(b).copied().unwrap();
                sort_key(&events[ia]).cmp(&sort_key(&events[ib]))
            });

            for child in sorted_children {
                if let Some(entry) = indegree.get_mut(&child) {
                    *entry -= 1;
                    if *entry == 0 {
                        queue.push_back(child);
                    }
                }
            }
        }
    }

    if visited != events.len() {
        return Err("cycle detected in event DAG".to_string());
    }

    Ok(())
}

pub fn topological_order(events: &[VectorEvent]) -> Result<Vec<VectorEvent>, String> {
    validate_dag(events)?;

    let mut event_map = BTreeMap::<String, VectorEvent>::new();
    let mut indegree = BTreeMap::<String, usize>::new();
    let mut children = BTreeMap::<String, Vec<String>>::new();

    for event in events {
        event_map.insert(event.event_hash.clone(), event.clone());
        indegree.entry(event.event_hash.clone()).or_insert(0);
        children.entry(event.event_hash.clone()).or_default();
    }

    for event in events {
        for parent in &event.parent_hashes {
            *indegree.entry(event.event_hash.clone()).or_insert(0) += 1;
            children
                .entry(parent.clone())
                .or_default()
                .push(event.event_hash.clone());
        }
    }

    let mut ready = Vec::<String>::new();
    for (hash, deg) in &indegree {
        if *deg == 0 {
            ready.push(hash.clone());
        }
    }

    ready.sort_by(|a, b| {
        sort_key(event_map.get(a).unwrap()).cmp(&sort_key(event_map.get(b).unwrap()))
    });

    let mut ordered = Vec::with_capacity(events.len());

    while !ready.is_empty() {
        let node = ready.remove(0);

        let ev = event_map
            .get(&node)
            .ok_or_else(|| format!("missing node in event map: {node}"))?
            .clone();

        ordered.push(ev);

        let mut next_children = children.get(&node).cloned().unwrap_or_default();
        next_children.sort_by(|a, b| {
            sort_key(event_map.get(a).unwrap()).cmp(&sort_key(event_map.get(b).unwrap()))
        });

        for child in next_children {
            if let Some(entry) = indegree.get_mut(&child) {
                *entry -= 1;
                if *entry == 0 {
                    ready.push(child);
                }
            }
        }

        ready.sort_by(|a, b| {
            sort_key(event_map.get(a).unwrap()).cmp(&sort_key(event_map.get(b).unwrap()))
        });
    }

    if ordered.len() != events.len() {
        return Err(
            "topological ordering failed due to unresolved cycle or missing ancestry".to_string(),
        );
    }

    Ok(ordered)
}
