#include "auth.hpp"
#include "logger.hpp"

#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <sys/socket.h>

#include <vector>

bool Authenticator::authenticateClient(int client_socket,
                                       const std::string& public_key_pem) {
  writeLog(LogLevel::INFO, "[auth] Starting authentication for socket " + std::to_string(client_socket));

  // Generate a 32-byte random challenge
  std::vector<unsigned char> challenge(32);
  if (RAND_bytes(challenge.data(), challenge.size()) != 1) {
    writeLog(LogLevel::ERROR, "[auth] Failed to generate cryptographic challenge for socket " + std::to_string(client_socket));
    return false;
  }
  writeLog(LogLevel::INFO, "[auth] Successfully generated 32-byte challenge.");

  // Send challenge length and challenge bytes to client
  uint32_t chal_len_net = htonl(static_cast<uint32_t>(challenge.size()));
  if (send(client_socket, &chal_len_net, sizeof(chal_len_net), 0) <= 0) {
    writeLog(LogLevel::ERROR, "[auth] Failed to send challenge length to socket " + std::to_string(client_socket));
    return false;
  }
  if (send(client_socket, challenge.data(), challenge.size(), 0) <= 0) {
    writeLog(LogLevel::ERROR, "[auth] Failed to send challenge payload to socket " + std::to_string(client_socket));
    return false;
  }
  writeLog(LogLevel::INFO, "[auth] Dispatched challenge to client socket " + std::to_string(client_socket) + ". Awaiting signature...");

  // Receive signature length and signature from client
  uint32_t sig_len_net = 0;
  if (recv(client_socket, &sig_len_net, sizeof(sig_len_net), MSG_WAITALL) <= 0) {
    writeLog(LogLevel::ERROR, "[auth] Failed to receive signature length from socket " + std::to_string(client_socket));
    return false;
  }
  uint32_t sig_len = ntohl(sig_len_net);
  if (sig_len == 0 || sig_len > 1024) {
    writeLog(LogLevel::WARNING, "[auth] Received invalid signature length (" + std::to_string(sig_len) + ") from socket " + std::to_string(client_socket));
    return false;
  }
  writeLog(LogLevel::INFO, "[auth] Expecting signature of length " + std::to_string(sig_len) + " bytes.");

  std::vector<unsigned char> signature(sig_len);
  if (recv(client_socket, signature.data(), sig_len, MSG_WAITALL) <= 0) {
    writeLog(LogLevel::ERROR, "[auth] Failed to receive full signature payload from socket " + std::to_string(client_socket));
    return false;
  }
  writeLog(LogLevel::INFO, "[auth] Signature received successfully. Proceeding with verification.");

  // Load public key
  BIO* bio = BIO_new_mem_buf(public_key_pem.data(),
                             static_cast<int>(public_key_pem.size()));
  if (!bio) {
    writeLog(LogLevel::ERROR, "[auth] Failed to allocate memory BIO for public key.");
    return false;
  }
  
  EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  if (!pkey) {
    writeLog(LogLevel::ERROR, "[auth] Failed to extract EVP_PKEY from PEM public key for socket " + std::to_string(client_socket));
    return false;
  }

  // Verify signature Ed25519 (Message Digest Context)
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) {
    writeLog(LogLevel::ERROR, "[auth] Failed to create EVP_MD_CTX context.");
    EVP_PKEY_free(pkey);
    return false;
  }

  bool verified = false;
  if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
    writeLog(LogLevel::INFO, "[auth] Digest context successfully initialized.");
    if (EVP_DigestVerify(ctx, signature.data(), signature.size(),
                         challenge.data(), challenge.size()) == 1) {
      verified = true;
      writeLog(LogLevel::INFO, "[auth] Signature successfully verified for socket " + std::to_string(client_socket));
    } else {
      writeLog(LogLevel::WARNING, "[auth] Signature verification failed (mismatch) for socket " + std::to_string(client_socket));
    }
  } else {
    writeLog(LogLevel::ERROR, "[auth] EVP_DigestVerifyInit failed during setup.");
  }

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  
  return verified;
}