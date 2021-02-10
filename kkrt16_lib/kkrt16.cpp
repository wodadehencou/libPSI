
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Network/IOService.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"
#include "libPSI/PSI/Kkrt/KkrtPsiReceiver.h"
#include "libPSI/PSI/Kkrt/KkrtPsiSender.h"
#include "kkrt16.h"
#include <bits/stdint-uintn.h>

const std::string EP_NAME = "kkrt16_psi";

std::vector<osuCrypto::block> load_input(Block* set, uint64_t size) {
  std::vector<osuCrypto::block> ret(size);
  for (uint64_t i=0; i<size; i++) {
    ret[i] = osuCrypto::toBlock(set[i].high, set[i].low);
  }
  return ret;
}

  // void run_sender(osuCrypto::PRNG & rng,
  //                 osuCrypto::span<osuCrypto::block> sendSet,
  //                 osuCrypto::u64 sendSize, osuCrypto::u64 recvSize,
  //                 networkParams * network, bool malicious, int statSec) {
void run_sender(Block seeds, Block *sendSet, uint64_t sendSize,
                uint64_t recvSize, const char *server, int port,
                int malicious, int statSec) {

    std::cout << "sender" << std::endl;
    
    osuCrypto::PRNG rng(osuCrypto::toBlock(seeds.high, seeds.low));

    osuCrypto::IOService ios;
    osuCrypto::Endpoint ep(ios, std::string(server), port,
                              osuCrypto::EpMode::Client,
                           EP_NAME);
    osuCrypto::Channel sendChl = ep.addChannel();

    osuCrypto::KkrtNcoOtSender otSend0;
    otSend0.configure(malicious, statSec, 128);
    osuCrypto::u64 baseCount = otSend0.getBaseOTCount();
    std::vector<std::array<osuCrypto::block, 2>> sendBlks(baseCount);
    std::vector<osuCrypto::block> recvBlks(baseCount);
    osuCrypto::BitVector choices(baseCount);
    choices.randomize(rng);

    sendChl.recv(sendBlks);
    for (auto i = 0; i < baseCount; ++i) {
      recvBlks[i] = sendBlks[i][choices[i]];
    }
    otSend0.setBaseOts(recvBlks, choices);

    // KkrtPsiReceiver recv;
    osuCrypto::KkrtPsiSender send;

    send.init(sendSize, recvSize, statSec, sendChl, otSend0,
              rng.get<osuCrypto::block>());
    std::vector<osuCrypto::block> localSendSet = load_input(sendSet, sendSize);
    send.sendInput(localSendSet, sendChl);

    sendChl.close();
    ep.stop();
    ios.stop();
  }

  // std::vector<osuCrypto::u64> run_receiver(
  //     osuCrypto::PRNG & rng, osuCrypto::span<osuCrypto::block> recvSet,
  //     osuCrypto::u64 sendSize, osuCrypto::u64 recvSize, networkParams * network,
  //     bool malicious, int statSec) {
void run_receiver(uint64_t *intersection,
                  uint64_t *intersectionSize, Block seeds,
                  Block *recvSet, uint64_t sendSize,
                  uint64_t recvSize, const char *server, int port,
                  int malicious, int statSec) {

    std::cout << "receiver" << std::endl;

    osuCrypto::PRNG rng(osuCrypto::toBlock(seeds.high, seeds.low));

    osuCrypto::IOService ios;
    osuCrypto::Endpoint ep(ios, std::string(server), port,
                           osuCrypto::EpMode::Server,
                           EP_NAME);
    osuCrypto::Channel recvChl = ep.addChannel();

    osuCrypto::KkrtNcoOtReceiver otRecv0;
    otRecv0.configure(malicious, statSec, 128);

    osuCrypto::u64 baseCount = otRecv0.getBaseOTCount();
    std::vector<std::array<osuCrypto::block, 2>> sendBlks(baseCount);
    for (auto i = 0; i < baseCount; ++i) {
      sendBlks[i][0] = rng.get<osuCrypto::block>();
      sendBlks[i][1] = rng.get<osuCrypto::block>();
    }
    recvChl.send(sendBlks);
    otRecv0.setBaseOts(sendBlks);

    osuCrypto::KkrtPsiReceiver recv;
    recv.init(sendSize, recvSize, statSec, recvChl, otRecv0,
              osuCrypto::ZeroBlock);
    std::vector<osuCrypto::block> localRecvSet = load_input(recvSet, recvSize);
    recv.sendInput(localRecvSet, recvChl);

    //////////////// Output communication /////////////////
    // u64 sentData = recvChl.getTotalDataSent();
    // u64 recvData = recvChl.getTotalDataRecv();
    // u64 totalData = sentData + recvData;

    // std::cout << "Receiver sent communication: " << sentData / std::pow(2.0,
    // 20) << " MB\n"; std::cout << "Receiver received communication: " <<
    // recvData / std::pow(2.0, 20) << " MB\n"; std::cout << "Receiver total
    // communication: " << totalData / std::pow(2.0, 20) << " MB\n";

    recvChl.close();
    ep.stop();
    ios.stop();

    *intersectionSize = recv.mIntersection.size();
    for (uint64_t i = 0; i < *intersectionSize; ++i) {
      // ret[i] = recvSet[recv.mIntersection[i]];
      intersection[i] = recv.mIntersection[i];
    }
    return;
  }
