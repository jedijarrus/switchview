"""Login throttle: failed attempts per key within a sliding window, in process memory, with a bounded number of keys.

The caller picks the keys (main.login_local: one per identity, never the client address, which a client forges with X-Forwarded-For).
The state lives in the process like the rest of the single uvicorn worker's state (see the invariant in main.py).
"""
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Iterable


class LoginThrottle:
    """A key is blocked while it has `limit` failures younger than `window_s` seconds. Every call drops the keys whose failures all
    left the window; beyond `max_keys` keys, the ones whose last failure is oldest go as well, so whoever invents keys cannot grow the
    memory. A key keeps only its last `limit` failures, the ones that decide whether it is blocked."""

    def __init__(self, limit: int = 10, window_s: float = 60.0, max_keys: int = 4096, clock: Callable[[], float] = time.monotonic):
        self.limit = limit
        self.window_s = window_s
        self.max_keys = max_keys
        self._clock = clock
        self._fails: OrderedDict[str, deque[float]] = OrderedDict()    # key -> its failure times; keys in the order of their last one

    def blocked(self, keys: Iterable[str]) -> bool:
        """True if one of the keys has `limit` failures within the window."""
        now = self._expire()
        return any(self._recent(key, now) >= self.limit for key in keys)

    def fail(self, keys: Iterable[str]) -> None:
        """Records one failure for each of the keys."""
        now = self._expire()
        for key in keys:
            if key not in self._fails:
                self._fails[key] = deque(maxlen=self.limit)
            self._fails[key].append(now)
            self._fails.move_to_end(key)
        while len(self._fails) > self.max_keys:
            self._fails.popitem(last=False)

    def __len__(self) -> int:
        """The number of keys with a failure within the window."""
        self._expire()
        return len(self._fails)

    def _expire(self) -> float:
        """Drops every key whose last failure left the window (those keys sit at the front); returns the clock's time."""
        now = self._clock()
        while self._fails:
            key, times = next(iter(self._fails.items()))
            if now - times[-1] < self.window_s:
                break
            del self._fails[key]
        return now

    def _recent(self, key: str, now: float) -> int:
        """The number of failures of key within the window; drops its older ones."""
        times = self._fails.get(key)
        if times is None:
            return 0
        while times and now - times[0] >= self.window_s:
            times.popleft()
        return len(times)
