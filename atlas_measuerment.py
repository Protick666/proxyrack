from datetime import datetime
from ripe.atlas.cousteau import (
  AtlasSource,
  AtlasCreateRequest,
  Dns
)

ATLAS_API_KEY = "b502ff34-3c69-477a-85f3-541efdce6afd"

dns_measurement = Dns(
    af="4",
    description="dns-50-small-local",
    is_oneoff=False,
    resolve_on_probe=True
)

source = AtlasSource(
    type="area",
    value="WW",
    requested=5,
    tags={"include":["system-ipv4-works"]}
)