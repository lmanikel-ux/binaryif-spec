
import time
from collections import defaultdict, deque

class RateLimiter:
    def __init__(self, rpm: int):
        self.rpm = max(1, rpm)
        self.window = 60
        self.hits = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.time()
        q = self.hits[key]
        while q and (now - q[0]) > self.window:
            q.popleft()
        if len(q) >= self.rpm:
            return False
        q.append(now)
        return True
