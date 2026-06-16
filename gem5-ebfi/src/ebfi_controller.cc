#include "ebfi_controller.hh"

#include <algorithm>

#include "base/logging.hh"
#include "base/stats/units.hh"
#include "sim/core.hh"

namespace gem5
{

namespace
{

EbfiController::Mode
parseMode(const std::string &mode)
{
    if (mode == "baseline") {
        return EbfiController::Mode::Baseline;
    }
    if (mode == "optimistic") {
        return EbfiController::Mode::Optimistic;
    }
    if (mode == "verified") {
        return EbfiController::Mode::Verified;
    }
    fatal("Unknown EBFI mode '%s'; expected baseline, optimistic, or verified",
          mode.c_str());
}

} // anonymous namespace

EbfiController::EbfiStats::EbfiStats(EbfiController *parent)
    : statistics::Group(parent),
      ADD_STAT(reads, statistics::units::Count::get(),
               "Read requests observed by the EBFI controller"),
      ADD_STAT(writes, statistics::units::Count::get(),
               "Write requests observed by the EBFI controller"),
      ADD_STAT(metadataHits, statistics::units::Count::get(),
               "Trusted-version cache hits"),
      ADD_STAT(metadataMisses, statistics::units::Count::get(),
               "Trusted-version cache misses"),
      ADD_STAT(aeadQueueTicks, statistics::units::Tick::get(),
               "Ticks waiting to issue into the pipelined AEAD engine"),
      ADD_STAT(metadataQueueTicks, statistics::units::Tick::get(),
               "Ticks waiting to issue on the authenticated metadata path"),
      ADD_STAT(writeControlQueueTicks, statistics::units::Tick::get(),
               "Ticks waiting to issue reservation or commit persistence"),
      ADD_STAT(writeReservationTicks, statistics::units::Tick::get(),
               "Total modeled reservation-persistence delay"),
      ADD_STAT(writeCommitTicks, statistics::units::Tick::get(),
               "Total modeled commit-journal and publication delay"),
      ADD_STAT(controllerReadTicks, statistics::units::Tick::get(),
               "Total read delay added by EBFI"),
      ADD_STAT(controllerWriteTicks, statistics::units::Tick::get(),
               "Total write delay added by EBFI"),
      ADD_STAT(endToEndReadTicks, statistics::units::Tick::get(),
               "Total read latency measured at the EBFI boundary"),
      ADD_STAT(endToEndWriteTicks, statistics::units::Tick::get(),
               "Total write latency measured at the EBFI boundary"),
      ADD_STAT(optimisticLateChecks, statistics::units::Count::get(),
               "Optimistic responses released before metadata verification"),
      ADD_STAT(optimisticLateCheckTicks, statistics::units::Tick::get(),
               "Aggregate post-release verification window"),
      ADD_STAT(ratchets, statistics::units::Count::get(),
               "Modeled HKDF epoch ratchets")
{
}

EbfiController::EbfiController(const EbfiControllerParams &p)
    : MemDelay(p),
      mode(parseMode(p.mode)),
      lineSize(p.line_size),
      aeadLatency(p.aead_latency),
      aeadIssueLatency(p.aead_issue_latency),
      metadataEntries(p.metadata_cache_entries),
      metadataAssoc(p.metadata_cache_assoc),
      metadataSets(metadataEntries == 0 || metadataAssoc == 0 ? 0 :
                   metadataEntries / metadataAssoc),
      metadataHitLatency(p.metadata_hit_latency),
      metadataMissLatency(p.metadata_miss_latency),
      metadataIssueLatency(p.metadata_issue_latency),
      writeReservationLatency(p.write_reservation_latency),
      writeCommitLatency(p.write_commit_latency),
      writeControlIssueLatency(p.write_control_issue_latency),
      ratchetEveryWrites(p.ratchet_every_writes),
      hkdfLatency(p.hkdf_latency),
      metadataCache(metadataSets),
      stats(this)
{
    fatal_if(lineSize == 0, "line_size must be non-zero");
    fatal_if(metadataEntries > 0 && metadataAssoc == 0,
             "metadata_cache_assoc must be non-zero");
    fatal_if(metadataEntries > 0 &&
             metadataEntries % metadataAssoc != 0,
             "metadata_cache_entries must be divisible by associativity");
}

std::pair<bool, Tick>
EbfiController::lookupMetadata(Addr addr)
{
    if (metadataEntries == 0) {
        stats.metadataMisses++;
        return {false, metadataMissLatency};
    }

    const Addr line = addr / lineSize;
    auto &set = metadataCache[line % metadataSets];
    const auto it = std::find(set.begin(), set.end(), line);
    if (it != set.end()) {
        set.erase(it);
        set.push_front(line);
        stats.metadataHits++;
        return {true, metadataHitLatency};
    }

    if (set.size() == metadataAssoc) {
        set.pop_back();
    }
    set.push_front(line);
    stats.metadataMisses++;
    return {false, metadataMissLatency};
}

void
EbfiController::touchMetadata(Addr addr)
{
    if (metadataEntries == 0) {
        return;
    }

    const Addr line = addr / lineSize;
    auto &set = metadataCache[line % metadataSets];
    const auto it = std::find(set.begin(), set.end(), line);
    if (it != set.end()) {
        set.erase(it);
    } else if (set.size() == metadataAssoc) {
        set.pop_back();
    }
    set.push_front(line);
}

Tick
EbfiController::scheduleMetadata(Tick ready, Tick latency)
{
    const Tick start = std::max(ready, metadataNextIssue);
    stats.metadataQueueTicks += start - ready;
    metadataNextIssue = start + metadataIssueLatency;
    return start + latency;
}

Tick
EbfiController::scheduleAead(Tick ready)
{
    const Tick start = std::max(ready, aeadNextIssue);
    stats.aeadQueueTicks += start - ready;
    aeadNextIssue = start + aeadIssueLatency;
    return start + aeadLatency;
}

Tick
EbfiController::scheduleWriteControl(Tick ready, Tick latency)
{
    if (latency == 0) {
        return ready;
    }
    const Tick start = std::max(ready, writeControlNextIssue);
    stats.writeControlQueueTicks += start - ready;
    writeControlNextIssue = start + writeControlIssueLatency;
    return start + latency;
}

Tick
EbfiController::scheduleRatchet(Tick ready)
{
    const Tick start = std::max(ready, ratchetNextIssue);
    ratchetNextIssue = start + hkdfLatency;
    stats.ratchets++;
    return ratchetNextIssue;
}

Tick
EbfiController::delayReq(PacketPtr pkt)
{
    RequestState state;
    state.requestTick = curTick();
    state.isRead = pkt->isRead();
    state.isWrite = pkt->isWrite();

    if (state.isRead) {
        stats.reads++;
    } else if (state.isWrite) {
        stats.writes++;
    }

    if (mode == Mode::Baseline) {
        requests[pkt] = state;
        return 0;
    }

    if (state.isRead) {
        const auto [hit, latency] = lookupMetadata(pkt->getAddr());
        state.metadataHit = hit;
        state.metadataLatency = latency;

        // Optimistic mode starts the authenticated metadata lookup with the
        // data request. Verified mode deliberately serializes it after the
        // data response, matching the conservative design in the paper.
        if (mode == Mode::Optimistic) {
            state.metadataReady = scheduleMetadata(curTick(), latency);
        }
        requests[pkt] = state;
        return 0;
    }

    if (state.isWrite) {
        Tick finish = scheduleWriteControl(
            curTick(), writeReservationLatency);
        stats.writeReservationTicks += finish - curTick();
        finish = scheduleAead(finish);
        writesSinceRatchet++;
        if (ratchetEveryWrites != 0 &&
            writesSinceRatchet >= ratchetEveryWrites) {
            finish = scheduleRatchet(finish);
            writesSinceRatchet = 0;
        }
        const Tick delay = finish - curTick();
        stats.controllerWriteTicks += delay;
        requests[pkt] = state;
        return delay;
    }

    requests[pkt] = state;
    return 0;
}

Tick
EbfiController::delayResp(PacketPtr pkt)
{
    const auto it = requests.find(pkt);
    if (it == requests.end()) {
        return 0;
    }

    const RequestState state = it->second;
    requests.erase(it);

    if (state.isRead) {
        Tick delay = 0;
        if (mode == Mode::Optimistic) {
            const Tick release = scheduleAead(curTick());
            const Tick verificationDone =
                std::max(release, state.metadataReady);
            if (verificationDone > release) {
                stats.optimisticLateChecks++;
                stats.optimisticLateCheckTicks += verificationDone - release;
            }
            delay = release - curTick();
        } else if (mode == Mode::Verified) {
            const Tick metadataReady =
                scheduleMetadata(curTick(), state.metadataLatency);
            delay = scheduleAead(metadataReady) - curTick();
        }

        stats.controllerReadTicks += delay;
        stats.endToEndReadTicks +=
            curTick() + delay - state.requestTick;
        return delay;
    }

    if (state.isWrite) {
        const Tick finish =
            scheduleWriteControl(curTick(), writeCommitLatency);
        const Tick delay = finish - curTick();
        stats.writeCommitTicks += delay;
        stats.controllerWriteTicks += delay;
        touchMetadata(pkt->getAddr());
        stats.endToEndWriteTicks +=
            curTick() + delay - state.requestTick;
        return delay;
    }
    return 0;
}

} // namespace gem5
