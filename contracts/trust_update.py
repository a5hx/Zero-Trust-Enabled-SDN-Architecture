from dataclasses import dataclass, field
from typing import Literal
import time

@dataclass
class TrustUpdate:
    device_id:          str
    edge_node_id:       str
    timestamp:          float = field(default_factory=time.time)
    task_status:        Literal['success','failure','timeout'] = 'success'
    cpu_usage:          float = 0.0   # Actual CPU [0.0, 1.0]
    reported_cpu:       float = 0.0   # What the node claimed [0.0, 1.0]
    latency_ms:         float = 0.0   # Raw observed latency
    trust_score_before: float = 0.5
    trust_score_after:  float = 0.5
    anomaly_flag:       bool  = False

    def honesty_delta(self) -> float:
        # Deviation between reported and actual CPU — feeds H metric
        return abs(self.reported_cpu - self.cpu_usage)

    def to_dict(self) -> dict:
        return self.__dict__.copy()
