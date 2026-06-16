#ifndef __CXL_EBFI_CONTROLLER_HH__
#define __CXL_EBFI_CONTROLLER_HH__

#include <deque>
#include <string>
#include <unordered_map>
#include <vector>

#include "base/statistics.hh"
#include "mem/mem_delay.hh"
#include "params/EbfiController.hh"

namespace gem5
{

class EbfiController : public MemDelay
{
  public:
    explicit EbfiController(const EbfiControllerParams &params);

    enum class Mode
    {
        Baseline,
        Optimistic,
        Verified
    };

  protected:
    Tick delayReq(PacketPtr pkt) override;
    Tick delayResp(PacketPtr pkt) override;

  private:
    struct RequestState
    {
        Tick requestTick = 0;
        Tick metadataReady = 0;
        Tick metadataLatency = 0;
        bool metadataHit = false;
        bool isRead = false;
        bool isWrite = false;
    };

    struct EbfiStats : public statistics::Group
    {
        statistics::Scalar reads;
        statistics::Scalar writes;
        statistics::Scalar metadataHits;
        statistics::Scalar metadataMisses;
        statistics::Scalar aeadQueueTicks;
        statistics::Scalar metadataQueueTicks;
        statistics::Scalar writeControlQueueTicks;
        statistics::Scalar writeReservationTicks;
        statistics::Scalar writeCommitTicks;
        statistics::Scalar controllerReadTicks;
        statistics::Scalar controllerWriteTicks;
        statistics::Scalar endToEndReadTicks;
        statistics::Scalar endToEndWriteTicks;
        statistics::Scalar optimisticLateChecks;
        statistics::Scalar optimisticLateCheckTicks;
        statistics::Scalar ratchets;

        explicit EbfiStats(EbfiController *parent);
    };

    std::pair<bool, Tick> lookupMetadata(Addr addr);
    Tick scheduleMetadata(Tick ready, Tick latency);
    Tick scheduleAead(Tick ready);
    Tick scheduleWriteControl(Tick ready, Tick latency);
    Tick scheduleRatchet(Tick ready);
    void touchMetadata(Addr addr);

    const Mode mode;
    const unsigned lineSize;
    const Tick aeadLatency;
    const Tick aeadIssueLatency;
    const unsigned metadataEntries;
    const unsigned metadataAssoc;
    const unsigned metadataSets;
    const Tick metadataHitLatency;
    const Tick metadataMissLatency;
    const Tick metadataIssueLatency;
    const Tick writeReservationLatency;
    const Tick writeCommitLatency;
    const Tick writeControlIssueLatency;
    const unsigned ratchetEveryWrites;
    const Tick hkdfLatency;

    Tick aeadNextIssue = 0;
    Tick metadataNextIssue = 0;
    Tick writeControlNextIssue = 0;
    Tick ratchetNextIssue = 0;
    uint64_t writesSinceRatchet = 0;

    std::vector<std::deque<Addr>> metadataCache;
    std::unordered_map<PacketPtr, RequestState> requests;
    EbfiStats stats;
};

} // namespace gem5

#endif // __CXL_EBFI_CONTROLLER_HH__
