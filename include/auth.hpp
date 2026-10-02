#pragma once

#include <string>
#include <vector>

class Authenticator {
 private:
  // static std::vector<unsigned char> generateChallenge(size_t length = 32);
  // static bool verifySignature(const std::string& public_key_pem,
  //                             const std::vector<unsigned char>& challenge,
  //                             const std::vector<unsigned char>& signature);

 public:
 // static bool loadKey();

  // All above functions are not implemented yet
  static bool authenticateClient(int client_socket,
                                 const std::string& public_key_pem);
};