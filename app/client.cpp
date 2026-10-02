// All these OpenSSL libraries are in C language so we did not get the C++ RAII and smart pointer feature to use it in our project
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#define PORT 8080

// Pendig Files Offers to show
// Used for OFFERS command
struct PendingOffer {
  std::string sender;
  std::string filename;
  size_t file_size;
  std::string raw_notification;
};

// This mutex is used to use prending_file_offers map without problem of write 
std::mutex offers_mutex;
std::map<std::string, PendingOffer> pending_file_offers;

// This outgoing_mutex is used only to not get trapped in string active_outgoing_filepath variable write problem
std::mutex outgoing_mutex;
std::string active_outgoing_filepath;

// Mutex to protect all concurrent socket writes from main thread and background threads
std::mutex socket_mutex;


ssize_t safeSend(int sock, const void* buf, size_t len, int flags) {
  std::lock_guard<std::mutex> lock(socket_mutex);
  return send(sock, buf, len, flags);
}

bool signChallenge(
    const std::string& priv_key_path,  // Clent private key path secret place
    const std::vector<unsigned char>&challenge,  // Challenge of <random string/chars> that we have generated in the auth authenticateClient() function named challange
    std::vector<unsigned char>& signature) {  // This is a mathematical answer form client to the server

  // We don't have to use file.close() C++ RAII feature 
  std::ifstream f(priv_key_path);
  if (!f.is_open()) return false;

  // Insted of using string I use a sting stream which directly dumps all the file content in the ss variable
  std::stringstream ss;
  ss << f.rdbuf();

  // PEM stands for Privacy Enhanced Mail are Text style (Base64 encoded), This is DER but encoded
  // DER Dishtinguished Encoded Rules are Binary style 
  std::string pem = ss.str();

  // Basic Input and output for OpenSSL Abstract 
  BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  // EnVelop for Private key
  EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);

  // Drawback for c didn't have RAII
  BIO_free(bio);
  if (!pkey) return false;

  // Message Digest Context: It remembers the state of the operation which have performed before 
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();

  // This will useful to tell Digest what is the length of the signature 
  size_t sig_len = 0;
  
  bool success = false;

  // Initialisation of the DigetSign 
  if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
    // Finding the required sized signeature vector to the desire size
    if (EVP_DigestSign(ctx, nullptr, &sig_len, challenge.data(),
                       challenge.size()) == 1) {
      // Vecoter resized
      signature.resize(sig_len);
      if (EVP_DigestSign(ctx, signature.data(), &sig_len, challenge.data(),
                         challenge.size()) == 1) {
        // Resize if not necessary but it is a best practice to give thanks to C
        signature.resize(sig_len);
        success = true;
      }
    }
  }

  // Draw Back
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return success;
}

// Helper to read a complete line safely from the socket
// It is taking one charectre at a time so no race condition will happen every client will get chance to get atleat one word 
std::string readLine(int sock, bool& success) {
  std::string line;
  char c;
  while (true) {
    ssize_t r = read(sock, &c, 1);
    if (r <= 0) {
      success = false;
      return "";
    }
    if (c == '\n') break;
    line += c;
  }
  success = true;
  return line;
}

// Single-reader loop handling both chat messages and framed file chunks safely
void listenLoop(int sock) {
  // active_downloads have data about file which is going to send 
  // Like filename, ofstream object and size of the file
  static std::map<std::string, std::pair<std::ofstream, size_t>>
      active_downloads;

  // The main background loop in the entire client for listining
  while (true) {
    bool success = false;
    std::string line = readLine(sock, success);
    if (!success) {
      std::cout << "\n[Disconnected from server]\n";
      break;
    }

    // user not going to see it on the screen but in backend it is a custom format to transfer the data
    if (line.rfind("FILE_CHUNK:", 0) == 0) {
      size_t first_colon = line.find(':');
      size_t second_colon = line.rfind(':');
      std::string filename =
          line.substr(first_colon + 1, second_colon - (first_colon + 1));
      size_t chunk_size = std::stoull(line.substr(second_colon + 1));

      std::vector<char> chunk_buf(chunk_size);
      ssize_t total_read = 0;

      // This loop transfer the entire large file in chunks
      while (total_read < static_cast<ssize_t>(chunk_size)) {
        ssize_t bytes = recv(sock, chunk_buf.data() + total_read,
                             chunk_size - total_read, MSG_WAITALL);
        if (bytes <= 0) break;
        total_read += bytes;
      }

      // If the file transfers the first chunk it will create a file in the folder this client file present
      if (active_downloads.find(filename) == active_downloads.end()) {
        std::ofstream outfile(filename, std::ios::binary);
        active_downloads[filename] = {std::move(outfile), 0};
      }

      // Structure Bindings
      auto& [outfile, received_bytes] = active_downloads[filename];
      
      // on second time entire file one more time append in the exitsting file
      if (outfile.is_open()) {
        outfile.write(chunk_buf.data(), total_read);
        received_bytes += total_read;

        size_t total_file_size = 0;
        {
          std::lock_guard<std::mutex> lock(offers_mutex);
          for (const auto& pair : pending_file_offers) {
            if (pair.second.filename == filename) {
              total_file_size = pair.second.file_size;
              break;
            }
          }
        }

        // Progress Bar below
        if (total_file_size > 0) {
          int width = 25;
          float prog = static_cast<float>(received_bytes) / total_file_size;
          int filled = static_cast<int>(width * prog);
          std::string bar = "[";
          for (int i = 0; i < width; ++i) {
            if (i < filled)
              bar += "=";
            else if (i == filled)
              bar += ">";
            else
              bar += " ";
          }
          bar += "] " + std::to_string(static_cast<int>(prog * 100)) + "%";
          std::cout << "\r\33[K[Receiving] " << filename << " " << bar
                    << std::flush;

          // To end the file transfer we will use this block of it
          if (received_bytes >= total_file_size) {
            outfile.close();
            active_downloads.erase(filename);
            std::cout << "\n[Transfer] Successfully downloaded and saved: "
                      << filename << "\n> " << std::flush;
          }
        }
      }

    // This block will prepare the data to send if this client is the sender 
    // This block responsible to transfer the data
    } else if (line.rfind("READY_FOR_CHUNKS", 0) == 0) {
      std::string filepath_to_send;
      {
        // This mutex is used to transfer the next file only after current file sent
        std::lock_guard<std::mutex> lock(outgoing_mutex);
        filepath_to_send = active_outgoing_filepath;
        active_outgoing_filepath.clear();
      }


      if (!filepath_to_send.empty()) {
        // This thread helpful to see chats even the file is tranfering and this thread is in the detach mode
        std::thread([sock, filepath_to_send]() {
          namespace fs = std::filesystem;
          if (!fs::exists(filepath_to_send)) {
            std::cout << "\n[Error] Outgoing file no longer exists: "
                      << filepath_to_send << "\n> " << std::flush;
            return;
          }
          uintmax_t file_size = fs::file_size(filepath_to_send);
          std::ifstream infile(filepath_to_send, std::ios::binary);
          if (!infile.is_open()) {
            std::cout << "\n[Error] Could not open file for streaming: "
                      << filepath_to_send << "\n> " << std::flush;
            return;
          }
          // Works only after C++17
          constexpr size_t CHUNK_SIZE = 65536;
          std::vector<char> buffer(CHUNK_SIZE);
          size_t bytes_sent_total = 0;
          std::string filename_only =
              fs::path(filepath_to_send).filename().string();

          std::cout << "\n[Transfer] Recipient accepted. Streaming '"
                    << filename_only << "' (" << file_size << " bytes)...\n"
                    << std::flush;

          while (bytes_sent_total < file_size && infile) {
            infile.read(buffer.data(), CHUNK_SIZE);
            std::streamsize bytes_read = infile.gcount();
            if (bytes_read <= 0) break;

            std::string header = "FILE_UPLOAD:" + filename_only + ":" +
                                 std::to_string(bytes_read) + "\n";
            safeSend(sock, header.c_str(), header.length(), 0);
            ssize_t sent = safeSend(sock, buffer.data(), bytes_read, 0);
            if (sent <= 0) {
              std::cout
                  << "\n[Error] Connection lost during file transmission.\n";
              break;
            }
            bytes_sent_total += bytes_read;

            int width = 25;
            float prog = static_cast<float>(bytes_sent_total) / file_size;
            int filled = static_cast<int>(width * prog);
            std::string bar = "[";
            for (int i = 0; i < width; ++i) {
              if (i < filled)
                bar += "=";
              else if (i == filled)
                bar += ">";
              else
                bar += " ";
            }
            bar += "] " + std::to_string(static_cast<int>(prog * 100)) + "%";
            std::cout << "\r\33[K[Sending] " << filename_only << " " << bar
                      << std::flush;
          }

          infile.close();
          std::cout << "\n[Transfer] Broadcast complete. Chat is active.\n> "
                    << std::flush;
        }).detach();
      }
    } else if (line.rfind("[FILE_OFFER from", 0) == 0) {
      size_t from_pos = line.find("from ");
      size_t colon_pos = line.find("]: ");
      if (from_pos != std::string::npos && colon_pos != std::string::npos) {
        std::string sender =
            line.substr(from_pos + 5, colon_pos - (from_pos + 5));
        std::string details = line.substr(colon_pos + 3);
        size_t space_pos = details.find(' ');
        std::string filename = (space_pos != std::string::npos)
                                   ? details.substr(0, space_pos)
                                   : "incoming_file";
        size_t size_start = details.find('(');
        size_t size_end = details.find(" bytes)");
        size_t file_size = 0;
        if (size_start != std::string::npos && size_end != std::string::npos) {
          try {
            file_size = std::stoull(
                details.substr(size_start + 1, size_end - size_start - 1));
          } catch (...) {
          }
        }
        {
          std::lock_guard<std::mutex> lock(offers_mutex);
          pending_file_offers[sender] = {sender, filename, file_size, line};
        }
      }
      std::cout << "\r\33[K" << line
                << "\n[Notice] Type 'OFFERS' to view pending, "
                   "'FILE_ACCEPT:<Sender>' to download, or "
                   "'FILE_REJECT:<Sender>' to decline.\n> "
                << std::flush;
    } else {
      std::cout << "\r\33[K" << line << "\n> " << std::flush;
    }
  }
}

int main() {
  std::string priv_path = "client_private.pem";
  std::string pub_path = "client_public.pem";
  if (!std::ifstream(priv_path)) {
    std::cout << "[Client] Generating local Ed25519 key pair...\n";
    system("openssl genpkey -algorithm Ed25519 -out client_private.pem");
    system(
        "openssl pkey -in client_private.pem -pubout -out client_public.pem");
  }

  int sock = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in serv_addr;
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(PORT);
  inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

  if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
    std::cerr << "Connection failed. Is the server running?\n";
    return 1;
  }

  std::string password;
  std::cout << "Enter Server Access Password: ";
  std::cin >> password;
  safeSend(sock, password.c_str(), password.length(), 0);

  char gate_resp[32] = {0};
  read(sock, gate_resp, sizeof(gate_resp));
  if (std::string(gate_resp).rfind("AUTH_FAIL", 0) == 0) {
    std::cerr << "Access denied by server: Incorrect password.\n";
    close(sock);
    return 1;
  }

  std::string username;
  std::cout << "Enter your Username: ";
  std::cin >> username;
  safeSend(sock, username.c_str(), username.length(), 0);

  std::ifstream pub_file(pub_path);
  std::stringstream pss;
  pss << pub_file.rdbuf();
  std::string pub_str = pss.str();
  uint32_t key_len = htonl(static_cast<uint32_t>(pub_str.length()));
  safeSend(sock, &key_len, sizeof(key_len), 0);
  safeSend(sock, pub_str.c_str(), pub_str.length(), 0);

  uint32_t chal_len_net = 0;
  if (recv(sock, &chal_len_net, sizeof(chal_len_net), MSG_WAITALL) <= 0)
    return 1;
  uint32_t chal_len = ntohl(chal_len_net);
  std::vector<unsigned char> challenge(chal_len);
  recv(sock, challenge.data(), chal_len, MSG_WAITALL);

  std::vector<unsigned char> signature;
  if (!signChallenge(priv_path, challenge, signature)) {
    std::cerr << "Failed to sign the challenge.\n";
    return 1;
  }

  uint32_t sig_len = htonl(static_cast<uint32_t>(signature.size()));
  safeSend(sock, &sig_len, sizeof(sig_len), 0);
  safeSend(sock, signature.data(), signature.size(), 0);

  char status_buf[32] = {0};
  read(sock, status_buf, sizeof(status_buf));
  if (std::string(status_buf).rfind("HANDSHAKE_OK", 0) != 0) {
    std::cerr << "Authentication failed by server verified.\n";
    close(sock);
    return 1;
  }

  std::cout
      << "[Client] Authentication successful! Entering chat interface...\n";
  std::thread(listenLoop, sock).detach();

  std::string input;
  std::cin.clear();
  std::cin.ignore();
  std::cout
      << "\nCommands:\n"
      << "  PUB:<<message>> (Public Broadcast)\n"
      << "  PRV:<<user>>:<<message>> (Direct Message)\n"
      << "  LIST (View Online Users)\n"
      << "  FILE_OFFER:[User1,User2]:<<file_path>> (Broadcast File)\n"
      << "  OFFERS (View Pending Incoming File Offers)\n"
      << "  FILE_ACCEPT:<<Sender>> (Accept and Download File Offer)\n"
      << "  FILE_REJECT:<<Sender>> (Reject and Clear Pending File Offer)\n\n> ";

  // This is the starting point of the client program
  while (true) {
    // std::cin is the input source
    std::getline(std::cin, input);
    if (input.empty()) {
      std::cout << "> " << std::flush;
      continue;
    }

    if (input == "OFFERS") {
      std::lock_guard<std::mutex> lock(offers_mutex);
      std::cout << "\n=== Pending File Offers ===\n";
      if (pending_file_offers.empty()) {
        std::cout << "  No pending file offers.\n";
      } else {
        int idx = 1;
        for (const auto& pair : pending_file_offers) {
          std::cout << "  " << idx++ << ". From " << pair.second.sender << ": "
                    << pair.second.filename << " (" << pair.second.file_size
                    << " bytes)\n";
        }
      }
    } else if (input.rfind("FILE_REJECT:", 0) == 0) {
      std::string target_sender = input.substr(12);
      bool found = false;

      {
        std::lock_guard<std::mutex> lock(offers_mutex);
        auto it = pending_file_offers.find(target_sender);
        if (it != pending_file_offers.end()) {
          pending_file_offers.erase(it);
          found = true;
        }
      }

      if (!found) {
        std::cout << "[Error] No pending offer found from sender: "
                  << target_sender << "\n";
      } else {
        std::string reject_msg = "FILE_REJECT:" + target_sender + "\n";
        safeSend(sock, reject_msg.c_str(), reject_msg.length(), 0);
        std::cout
            << "[Transfer] Successfully rejected and removed file offer from "
            << target_sender << ".\n";
      }
    } else if (input.rfind("FILE_ACCEPT:", 0) == 0) {
      std::string target_sender = input.substr(12);
      bool found = false;

      {
        std::lock_guard<std::mutex> lock(offers_mutex);
        if (pending_file_offers.find(target_sender) !=
            pending_file_offers.end()) {
          found = true;
        }
      }

      if (!found) {
        std::cout << "[Error] No pending offer found from sender: "
                  << target_sender << "\n";
        std::cout << "> " << std::flush;
        continue;
      }

      std::string accept_msg = "FILE_ACCEPT:" + target_sender + "\n";
      safeSend(sock, accept_msg.c_str(), accept_msg.length(), 0);
    } else if (input.rfind("FILE_OFFER:", 0) == 0) {
      size_t bracket_start = input.find('[');
      size_t bracket_end = input.find(']');
      size_t path_delimiter = input.rfind(':');

      if (bracket_start == std::string::npos ||
          bracket_end == std::string::npos ||
          path_delimiter == std::string::npos) {
        std::cout << "[Error] Invalid format. Use: "
                     "FILE_OFFER:[Recipient1,Recipient2]:/path/to/file\n";
        std::cout << "> " << std::flush;
        continue;
      }

      std::string recipients_part =
          input.substr(bracket_start, bracket_end - bracket_start + 1);
      std::string file_path_str = input.substr(path_delimiter + 1);

      file_path_str.erase(0, file_path_str.find_first_not_of(" \t\"'"));
      file_path_str.erase(file_path_str.find_last_not_of(" \t\"'") + 1);

      namespace fs = std::filesystem;
      fs::path file_path(file_path_str);

      if (!fs::exists(file_path) || !fs::is_regular_file(file_path)) {
        std::cout << "[Error] File does not exist or is invalid: "
                  << file_path_str << "\n";
        std::cout << "> " << std::flush;
        continue;
      }

      uintmax_t file_size = fs::file_size(file_path);
      std::string filename = file_path.filename().string();

      {
        std::lock_guard<std::mutex> lock(outgoing_mutex);
        active_outgoing_filepath = file_path.string();
      }

      std::string server_offer_msg = "FILE_OFFER:" + recipients_part + ":" +
                                     std::to_string(file_size) + ":" +
                                     filename + "\n";
      safeSend(sock, server_offer_msg.c_str(), server_offer_msg.length(), 0);
      std::cout << "[Transfer] File offer sent. Waiting for recipient "
                   "acceptance...\n";
    } else {
      std::string chat_msg = input + "\n";
      safeSend(sock, chat_msg.c_str(), chat_msg.length(), 0);
    }
    std::cout << "> " << std::flush;
  }

  close(sock);
  return 0;
}