#!/usr/bin/env python3
"""
Standalone trust calculator for convergence demonstration.
Implements the EMA-based trust formula without external dependencies.
"""

import json
from typing import Dict, List, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class PacketEvent:
    """Represents a single packet-level event in the network."""
    timestamp: float
    switch_id: str
    event_type: str  # 'success', 'failure', 'wrong_dest', 'timeout', 'resource_lie'
    latency_ms: float
    reported_cpu: float
    actual_cpu: float
    details: str = ""


@dataclass
class TrustState:
    """Trust state for a single switch/node."""
    node_id: str
    trust_score: float
    reputation: float  # R component
    behavior: float    # B component
    honesty: float     # H component
    anomaly: float     # A component
    event_count: int
    last_update: float


class TrustComputeEngine:
    """
    Computes trust scores from scratch based on packet-level events.
    No external references - all values start from initial_score.
    """
    
    def __init__(
        self,
        alpha: float = 0.35,    # Reputation weight
        beta: float = 0.25,     # Behavior weight
        gamma: float = 0.25,    # Honesty weight
        delta: float = 0.15,    # Anomaly weight
        lambda_decay: float = 0.85,
        initial_score: float = 0.5
    ):
        """Initialize trust engine with formula parameters."""
        # Validate weights sum to 1.0
        weight_sum = round(alpha + beta + gamma + delta, 10)
        assert weight_sum == 1.0, f"Weights must sum to 1.0, got {weight_sum}"
        
        self.alpha = alpha
        self.beta = beta
        self.gamma = gamma
        self.delta = delta
        self.lambda_decay = lambda_decay
        self.initial_score = initial_score
        
        # Per-node state
        self.states: Dict[str, TrustState] = {}
        
        # History for analysis
        self.history: List[Tuple[float, str, float, Dict[str, float]]] = []
        
        print(f"Trust Engine Initialized:")
        print(f"  α={alpha} (Reputation)")
        print(f"  β={beta} (Behavior)")
        print(f"  γ={gamma} (Honesty)")
        print(f"  δ={delta} (Anomaly)")
        print(f"  λ={lambda_decay} (EMA decay)")
        print(f"  Initial Score={initial_score}")
    
    def _init_node(self, node_id: str, timestamp: float) -> None:
        """Initialize a new node with base values (NO external references)."""
        self.states[node_id] = TrustState(
            node_id=node_id,
            trust_score=self.initial_score,
            reputation=self.initial_score,
            behavior=self.initial_score,
            honesty=self.initial_score,
            anomaly=0.0,  # No anomaly initially
            event_count=0,
            last_update=timestamp
        )
        print(f"\n[NEW NODE] {node_id} initialized at trust={self.initial_score}")
    
    def process_event(self, event: PacketEvent) -> TrustState:
        """
        Process a packet event and update trust.
        This is where trust is COMPUTED from actual network behavior.
        """
        node_id = event.switch_id
        
        # Initialize node if first time seeing it
        if node_id not in self.states:
            self._init_node(node_id, event.timestamp)
        
        state = self.states[node_id]
        lam = self.lambda_decay
        
        # === COMPUTE RAW COMPONENT VALUES FROM EVENT ===
        
        # Reputation (R): Based on task success/failure
        if event.event_type == 'success':
            r_raw = 1.0
        elif event.event_type == 'failure' or event.event_type == 'wrong_dest':
            r_raw = 0.0
        elif event.event_type == 'timeout':
            r_raw = 0.3
        else:
            r_raw = 0.5
        
        # Behavior (B): Based on latency (lower is better)
        # Normalize: 0ms=1.0, 500ms=0.0
        b_raw = max(0.0, 1.0 - event.latency_ms / 500.0)
        
        # Honesty (H): Based on CPU reporting accuracy
        # Normalize: 0 delta=1.0, 0.5 delta=0.0
        cpu_delta = abs(event.reported_cpu - event.actual_cpu)
        h_raw = max(0.0, 1.0 - cpu_delta / 0.5)
        
        # Anomaly (A): Flag anomalous behavior
        is_anomalous = (
            event.event_type == 'wrong_dest' or
            event.event_type == 'resource_lie' or
            cpu_delta > 0.4
        )
        a_raw = 1.0 if is_anomalous else 0.0
        
        # === APPLY EMA SMOOTHING ===
        state.reputation = lam * r_raw + (1 - lam) * state.reputation
        state.behavior = lam * b_raw + (1 - lam) * state.behavior
        state.honesty = lam * h_raw + (1 - lam) * state.honesty
        state.anomaly = lam * a_raw + (1 - lam) * state.anomaly
        
        # === COMPUTE FINAL TRUST SCORE ===
        trust_before = state.trust_score
        state.trust_score = (
            self.alpha * state.reputation +
            self.beta * state.behavior +
            self.gamma * state.honesty -
            self.delta * state.anomaly
        )
        # Clip to [0, 1]
        state.trust_score = max(0.0, min(1.0, state.trust_score))
        
        # Update metadata
        state.event_count += 1
        state.last_update = event.timestamp
        
        # Record history
        self.history.append((
            event.timestamp,
            node_id,
            state.trust_score,
            {
                'R': state.reputation,
                'B': state.behavior,
                'H': state.honesty,
                'A': state.anomaly
            }
        ))
        
        # Log the update
        print(f"\n[t={event.timestamp:.2f}s] {node_id} | {event.event_type}")
        print(f"  Event: {event.details}")
        print(f"  Raw: R={r_raw:.2f} B={b_raw:.2f} H={h_raw:.2f} A={a_raw:.0f}")
        print(f"  EMA: R={state.reputation:.3f} B={state.behavior:.3f} "
              f"H={state.honesty:.3f} A={state.anomaly:.3f}")
        print(f"  Trust: {trust_before:.4f} → {state.trust_score:.4f} "
              f"(Δ={state.trust_score-trust_before:+.4f})")
        
        return state
    
    def get_all_states(self) -> Dict[str, TrustState]:
        """Get current trust state for all nodes."""
        return self.states.copy()
    
    def export_history(self, filename: str = 'trust_evolution.json') -> None:
        """Export complete trust history to JSON for analysis."""
        data = {
            'parameters': {
                'alpha': self.alpha,
                'beta': self.beta,
                'gamma': self.gamma,
                'delta': self.delta,
                'lambda_decay': self.lambda_decay,
                'initial_score': self.initial_score
            },
            'history': [
                {
                    'timestamp': t,
                    'node_id': nid,
                    'trust_score': ts,
                    'components': comp
                }
                for t, nid, ts, comp in self.history
            ],
            'final_states': {
                nid: asdict(state) for nid, state in self.states.items()
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"\n✓ Trust evolution exported to {filename}")
        return filename
