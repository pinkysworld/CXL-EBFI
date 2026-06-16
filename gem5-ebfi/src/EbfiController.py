from m5.objects.MemDelay import MemDelay
from m5.params import *


class EbfiController(MemDelay):
    type = "EbfiController"
    cxx_header = "ebfi_controller.hh"
    cxx_class = "gem5::EbfiController"

    mode = Param.String(
        "baseline", "baseline, optimistic, or verified"
    )
    line_size = Param.Unsigned(64, "Protected memory-line size in bytes")

    aead_latency = Param.Latency(
        "25ns", "Latency of one 64-byte AES-GCM operation"
    )
    aead_issue_latency = Param.Latency(
        "4ns", "Minimum issue interval of the pipelined AES-GCM engine"
    )

    metadata_cache_entries = Param.Unsigned(
        4096, "Number of trusted-version entries cached at the host"
    )
    metadata_cache_assoc = Param.Unsigned(
        4, "Associativity of the trusted-version cache"
    )
    metadata_hit_latency = Param.Latency(
        "4ns", "Trusted-version cache hit latency"
    )
    metadata_miss_latency = Param.Latency(
        "80ns", "Authenticated trusted-version miss latency"
    )
    metadata_issue_latency = Param.Latency(
        "2ns", "Minimum issue interval of the metadata path"
    )

    write_reservation_latency = Param.Latency(
        "0ns",
        "Configured persistence latency for counter high-watermark and intent",
    )
    write_commit_latency = Param.Latency(
        "0ns",
        "Configured latency for redo persistence and descriptor publication",
    )
    write_control_issue_latency = Param.Latency(
        "2ns", "Minimum issue interval of the modeled write-control path"
    )

    ratchet_every_writes = Param.Unsigned(
        4096, "Run one HKDF ratchet after this many writes; zero disables it"
    )
    hkdf_latency = Param.Latency(
        "80ns", "Latency of the modeled hardware HKDF ratchet"
    )
