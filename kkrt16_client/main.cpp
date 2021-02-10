
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Crypto/Blake2.h"
#include "cryptoTools/Network/Endpoint.h"
#include "cryptoTools/Network/IOService.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"
#include "libPSI/PSI/Kkrt/KkrtPsiReceiver.h"
#include "libPSI/PSI/Kkrt/KkrtPsiSender.h"
#include <algorithm>
#include <emmintrin.h>
#include <fstream>
#include <stdio.h>
#include <string>

const std::string EP_NAME = "kkrt16_psi";

struct networkParams {
  bool networkServer;
  std::string address;
  int port;
};

// commadline arguments
std::vector<std::string> inFileOpt{"in"};
std::vector<std::string> outFileOpt{"out"};
std::vector<std::string> roleOpt{"role"};
std::vector<std::string> sendSizeOpt{"ss", "sendsize"};
std::vector<std::string> recvSizeOpt{"rs", "recvsize"};
std::vector<std::string> networkServerOpt{"server", "netserver"};
std::vector<std::string> addressOpt{"addr", "address"};
std::vector<std::string> portOpt{"port"};
std::vector<std::string> seedOpt{"seed"};
std::vector<std::string> maliciousSecureOpt{"malicious"};
std::vector<std::string> statSecOpt{"statsec"};
std::vector<std::string> helpOpt{"h", "help"};

void print_help() { std::cout << "help messages" << std::endl; }

// not supported ABCDEEF
unsigned char hextoint(char in) {
  unsigned char const x = in;
  return x < 58 ? x - 48 : x - 87;
}

// input file should contain only one column
// every column is a hex string of 128bit(16Byte, 32chars)
// MUST be lower case 0-9a-f
std::vector<osuCrypto::block> load_input(std::string fileName) {
  std::vector<osuCrypto::block> ret;

  FILE *fp = fopen(fileName.c_str(), "r");
  if (fp == NULL)
    exit(EXIT_FAILURE);
  
  osuCrypto::Blake2 sha;
  osuCrypto::u8 digest[16];

  char *line = NULL;
  size_t len = 0;

  while ((getline(&line, &len, fp)) != -1) {

    sha.Reset(16);
    sha.Update(line, len);
    sha.Final(digest);
    ret.push_back(osuCrypto::block(
      digest[0],
      digest[1],
      digest[2],
      digest[3],
      digest[4],
      digest[5],
      digest[6],
      digest[7],
      digest[8],
      digest[9],
      digest[10],
      digest[11],
      digest[12],
      digest[13],
      digest[14],
      digest[15]
      ));

    // if (len < 32) {
    //   printf("length not valid line = %s", line);
    //   exit(EXIT_FAILURE);
    // }
    // // line must has fixed 32chars
	// unsigned char char15 = (hextoint(*line) << 4) | hextoint(*(line+1));
	// unsigned char char14 = (hextoint(*(line+2)) << 4) | hextoint(*(line+3));
	// unsigned char char13 = (hextoint(*(line+4)) << 4) | hextoint(*(line+5));
	// unsigned char char12 = (hextoint(*(line+6)) << 4) | hextoint(*(line+7));
	// unsigned char char11 = (hextoint(*(line+8)) << 4) | hextoint(*(line+9));
	// unsigned char char10 = (hextoint(*(line+10)) << 4) | hextoint(*(line+11));
	// unsigned char char9 = (hextoint(*(line+12)) << 4) | hextoint(*(line+13));
	// unsigned char char8 = (hextoint(*(line+14)) << 4) | hextoint(*(line+15));
	// unsigned char char7 = (hextoint(*(line+16)) << 4) | hextoint(*(line+17));
	// unsigned char char6 = (hextoint(*(line+18)) << 4) | hextoint(*(line+19));
	// unsigned char char5 = (hextoint(*(line+20)) << 4) | hextoint(*(line+21));
	// unsigned char char4 = (hextoint(*(line+22)) << 4) | hextoint(*(line+23));
	// unsigned char char3 = (hextoint(*(line+24)) << 4) | hextoint(*(line+25));
	// unsigned char char2 = (hextoint(*(line+26)) << 4) | hextoint(*(line+27));
	// unsigned char char1 = (hextoint(*(line+28)) << 4) | hextoint(*(line+29));
	// unsigned char char0 = (hextoint(*(line+30)) << 4) | hextoint(*(line+31));

    // ret.push_back(osuCrypto::block(char15, char14, char13, char12, char11,
    //                                   char10, char9, char8, char7, char6, char5,
    //                                   char4, char3, char2, char1, char0));
  }
  fclose(fp);
  if (line)
    free(line);
  return ret;
}

void store_output(std::string fileName, std::vector<osuCrypto::block> set) {
  std::ofstream myFile;
  myFile.open(fileName);
  if (myFile.is_open()) {
    for (auto i = 0; i < set.size(); i++) {
      myFile << set[i] << std::endl;
    }
    myFile.close();
  } else {
    exit(EXIT_FAILURE);
  }
}

void store_output2(std::string inFileName, std::string outFileName,
                   std::vector<osuCrypto::u64> set) {
  std::ifstream iFile;
  iFile.open(inFileName);
  std::ofstream oFile;
  oFile.open(outFileName);
  std::string line;
  osuCrypto::u64 inIdx = 0;
  osuCrypto::u64 sIdx = 0;
  if (iFile.is_open()) {
    if (oFile.is_open()) {
      while (getline(iFile, line)) {
        if (inIdx == set[sIdx]) {
          oFile << line << std::endl;
          sIdx++;
          if (sIdx == set.size())
            break;
        }
        inIdx++;
      }
      oFile.close();
    } else {
      iFile.close();
      exit(EXIT_FAILURE);
    }
  } else {
    exit(EXIT_FAILURE);
  }
}

  void run_sender(osuCrypto::PRNG & rng,
                  osuCrypto::span<osuCrypto::block> sendSet,
                  osuCrypto::u64 sendSize, osuCrypto::u64 recvSize,
                  networkParams * network, bool malicious, int statSec) {

    std::cout << "sender" << std::endl;

    osuCrypto::IOService ios;
    osuCrypto::Endpoint ep(ios, network->address, network->port,
                           network->networkServer ? osuCrypto::EpMode::Server
                                                  : osuCrypto::EpMode::Client,
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
    send.sendInput(sendSet, sendChl);

    sendChl.close();
    ep.stop();
    ios.stop();
  }

  std::vector<osuCrypto::u64> run_receiver(
      osuCrypto::PRNG & rng, osuCrypto::span<osuCrypto::block> recvSet,
      osuCrypto::u64 sendSize, osuCrypto::u64 recvSize, networkParams * network,
      bool malicious, int statSec) {

    std::cout << "receiver" << std::endl;

    osuCrypto::IOService ios;
    osuCrypto::Endpoint ep(ios, network->address, network->port,
                           network->networkServer ? osuCrypto::EpMode::Server
                                                  : osuCrypto::EpMode::Client,
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
    recv.sendInput(recvSet, recvChl);

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

    auto psi = recv.mIntersection.size();
    std::vector<osuCrypto::u64> ret(psi);
    for (auto i = 0; i < psi; ++i) {
      // ret[i] = recvSet[recv.mIntersection[i]];
      ret[i] = recv.mIntersection[i];
    }
    std::sort(ret.begin(), ret.end());

    return ret;
  }

  int main(int argc, char **argv) {
    osuCrypto::CLP cmd;
    cmd.parse(argc, argv);

    cmd.setDefault(portOpt, "21021");
    cmd.setDefault(addressOpt, "127.0.0.1");
    cmd.setDefault(statSecOpt, "40");

    if (cmd.isSet(helpOpt)) {
      print_help();
      return 0;
    }

    if (cmd.isSet(inFileOpt) == false || cmd.isSet(outFileOpt) == false ||
        cmd.isSet(roleOpt) == false || cmd.isSet(seedOpt) == false) {
      print_help();
      return 1;
    }

    std::string role = cmd.get<std::string>(roleOpt);
    bool networkServer = cmd.isSet(networkServerOpt);

    // set prng seed
    // std::vector<osuCrypto::u64> seeds = cmd.getMany<osuCrypto::u64>(seedOpt);
    std::vector<int> seeds = cmd.getMany<int>(seedOpt);
    seeds.resize(4);
    osuCrypto::PRNG prng;
    prng.SetSeed(_mm_set_epi32(seeds[0], seeds[1], seeds[2], seeds[3]));

    std::cout << "argument test pass" << std::endl;

    std::vector<osuCrypto::block> inSet =
        load_input(cmd.get<std::string>(inFileOpt));
    std::cout << "load input file pass" << std::endl;

    networkParams network{networkServer, cmd.get<std::string>(addressOpt),
                          cmd.get<int>(portOpt)};

    if (role == "sender") {
      if (cmd.isSet(recvSizeOpt) == false) {
        print_help();
        return 1;
      }
      run_sender(prng, inSet, inSet.size(),
                 cmd.get<osuCrypto::u64>(recvSizeOpt), &network,
                 cmd.isSet(maliciousSecureOpt), cmd.get<int>(statSecOpt));
    } else if (role == "receiver") {
      if (cmd.isSet(sendSizeOpt) == false) {
        print_help();
        return 1;
      }
      std::vector<osuCrypto::u64> intersection = run_receiver(
          prng, inSet, cmd.get<osuCrypto::u64>(sendSizeOpt), inSet.size(),
          &network, cmd.isSet(maliciousSecureOpt), cmd.get<int>(statSecOpt));
      store_output2(cmd.get<std::string>(inFileOpt),
                    cmd.get<std::string>(outFileOpt), intersection);
    } else {
      print_help();
      return 1;
    }

    return 0;
  }
