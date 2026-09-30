from __future__ import annotations

import unittest
from unittest.mock import patch

from common.config import config
from common.services import validate_loopback_url


class ConfigTests(unittest.TestCase):
    def test_ipv6_loopback_url_is_bracketed_and_valid(self) -> None:
        with patch.object(config, "REMOTE_HOST", "::1"):
            url = config.remote_base_url(8001)

        self.assertEqual("http://[::1]:8001", url)
        validate_loopback_url(url)


if __name__ == "__main__":
    unittest.main()
