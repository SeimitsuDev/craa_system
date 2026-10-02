#include "socket.hpp"

#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <vector>

#include "auth.hpp"
#include "logger.hpp"


// get
TcpServer::TcpServer(int port, std::string password, size_t high_water_mark)
    : server_fd(-1),
      port(port),
      server_password(password),
      transfer_manager(high_water_mark) {
  writeLog(LogLevel::INFO, "[socket : TcpServer] Booting up the TCP server on port " + std::to_string(port) + " with high water mark " + std::to_string(high_water_mark));
  std::memset(&address, 0, sizeof(address));
  std::filesystem::create_directory("keys");
  std::filesystem::create_directory("uploads");
  writeLog(LogLevel::INFO, "[socket : TcpServer] Ensured 'keys' and 'uploads' directories exist on disk.");
}

TcpServer::~TcpServer() {
  writeLog(LogLevel::INFO, "[socket : ~TcpServer] Tearing down the server and cleaning up...");
  if (server_fd != -1) {
    close(server_fd);
    writeLog(LogLevel::INFO, "[socket : ~TcpServer] Master socket closed successfully.");
  }
}

void TcpServer::_handleError(const std::string& message) {
  writeLog(LogLevel::ERROR, "[socket : _handleError] fail - We hit a fatal error, preparing to throw exception: " + message);
  writeLog(LogLevel::ERROR, message + " || Error: " + std::strerror(errno));
  throw std::runtime_error(message + " || Error: " + std::strerror(errno));
}

void TcpServer::broadcastMessage(const std::string& sender,
                                 const std::string& message) {
  writeLog(LogLevel::INFO, "[socket : broadcastMessage] Preparing to broadcast a public message from user '" + sender + "'.");
  std::lock_guard<std::mutex> lock(clients_mutex);
  std::string payload = "[PUBLIC] " + sender + ": " + message + "\n";
  writeLog(LogLevel::INFO, "[socket : broadcastMessage] Got the clients lock. Broadcasting to " + std::to_string(active_clients.size()) + " connected clients.");
  for (const auto& pair : active_clients) {
    send(pair.first, payload.c_str(), payload.length(), 0);
  }
  writeLog(LogLevel::INFO, "[socket : broadcastMessage] Broadcast complete for sender '" + sender + "'.");
}

void TcpServer::sendDirectMessage(const std::string& sender,
                                  const std::string& recipient,
                                  const std::string& encrypted_payload) {
  writeLog(LogLevel::INFO, "[socket : sendDirectMessage] User '" + sender + "' is trying to whisper to '" + recipient + "'.");
  std::lock_guard<std::mutex> lock(clients_mutex);
  int target_socket = -1;
  for (const auto& pair : active_clients) {
    if (pair.second == recipient) {
      target_socket = pair.first;
      break;
    }
  }

  if (target_socket != -1) {
    writeLog(LogLevel::INFO, "[socket : sendDirectMessage] Found recipient '" + recipient + "' at socket " + std::to_string(target_socket) + ". Pushing the encrypted payload now.");
    std::string load =
        "[PRIVATE_ENCRYPTED from " + sender + "]: " + encrypted_payload + "\n";
    send(target_socket, load.c_str(), load.length(), 0);
  }
  if (target_socket == -1) {
    writeLog(LogLevel::WARNING, "[socket : sendDirectMessage] fail - Recipient '" + recipient + "' is not online. Dropping the message from '" + sender + "'.");
  }
}

void TcpServer::handleFileStreamBroadcast(
    int sender_socket, const std::vector<std::string>& recipient_names,
    size_t file_size, const std::string& filename) {
  writeLog(LogLevel::INFO, "[socket : handleFileStreamBroadcast] Starting file stream broadcast for '" + filename + "' (" + std::to_string(file_size) + " bytes) from socket " + std::to_string(sender_socket));
  constexpr size_t CHUNK_SIZE = 65536;
  std::vector<char> buffer(CHUNK_SIZE);

  std::vector<int> recipient_sockets;
  {
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (const auto& pair : active_clients) {
      if (std::find(recipient_names.begin(), recipient_names.end(),
                    pair.second) != recipient_names.end()) {
        recipient_sockets.push_back(pair.first);
      }
    }
  }
  writeLog(LogLevel::INFO, "[socket : handleFileStreamBroadcast] Found " + std::to_string(recipient_sockets.size()) + " online recipients out of " + std::to_string(recipient_names.size()) + " requested.");

  size_t bytes_transferred = 0;
  while (bytes_transferred < file_size) {
    std::string header_line;
    char c;
    while (read(sender_socket, &c, 1) > 0) {
      if (c == '\n') break;
      header_line += c;
    }
    if (header_line.empty()) {
      writeLog(LogLevel::WARNING, "[socket : handleFileStreamBroadcast] fail - Stream interrupted, empty header received. Aborting stream at " + std::to_string(bytes_transferred) + " bytes.");
      break;
    }

    size_t colon = header_line.rfind(':');
    if (colon == std::string::npos) {
      writeLog(LogLevel::WARNING, "[socket : handleFileStreamBroadcast] fail - Malformed header line: " + header_line);
      break;
    }
    size_t chunk_size = std::stoull(header_line.substr(colon + 1));
    if (chunk_size == 0) {
      writeLog(LogLevel::WARNING, "[socket : handleFileStreamBroadcast] Chunk size is 0, assuming end of file or error.");
      break;
    }

    if (buffer.size() < chunk_size) {
      buffer.resize(chunk_size);
    }
    ssize_t bytes_read =
        recv(sender_socket, buffer.data(), chunk_size, MSG_WAITALL);
    if (bytes_read <= 0) {
      writeLog(LogLevel::ERROR, "[socket : handleFileStreamBroadcast] fail - Network read error while fetching chunk. We got " + std::to_string(bytes_read) + " bytes instead of " + std::to_string(chunk_size));
      break;
    }

    std::string fwd_header =
        "FILE_CHUNK:" + filename + ":" + std::to_string(bytes_read) + "\n";
    for (int client_sock : recipient_sockets) {
      if (!transfer_manager.isClientDropped(client_sock)) {
        send(client_sock, fwd_header.c_str(), fwd_header.length(), 0);
        send(client_sock, buffer.data(), bytes_read, 0);
      } else {
        writeLog(LogLevel::WARNING, "[socket : handleFileStreamBroadcast] Skipping dropped client socket " + std::to_string(client_sock));
      }
    }

    bytes_transferred += bytes_read;
  }
  writeLog(LogLevel::INFO, "[socket : handleFileStreamBroadcast] Stream finished. Transferred " + std::to_string(bytes_transferred) + " out of " + std::to_string(file_size) + " bytes.");
}

void TcpServer::_handleClientSession(int client_socket) {
  writeLog(LogLevel::INFO, "[socket : _handleClientSession] New client connected on socket " + std::to_string(client_socket) + ". Starting authentication phase.");
  char pwd_buf[256] = {0};
  ssize_t bytes = read(client_socket, pwd_buf, sizeof(pwd_buf) - 1);
  if (bytes <= 0) {
    writeLog(LogLevel::ERROR, "[socket : _handleClientSession] fail - Failed to read password from socket " + std::to_string(client_socket) + ". Closing.");
    closeClient(client_socket);
    return;
  }
  std::string client_pwd(pwd_buf, bytes);
  if (client_pwd != server_password) {
    writeLog(LogLevel::WARNING, "[socket : _handleClientSession] fail - Bad password provided by socket " + std::to_string(client_socket) + ". Booting them out.");
    send(client_socket, "AUTH_FAIL: Incorrect Server Password\n", 37, 0);
    closeClient(client_socket);
    return;
  }
  writeLog(LogLevel::INFO, "[socket : _handleClientSession] Server password verified for socket " + std::to_string(client_socket));
  send(client_socket, "AUTH_OK\n", 8, 0);

  char user_buf[256] = {0};
  bytes = read(client_socket, user_buf, sizeof(user_buf) - 1);
  if (bytes <= 0) {
    writeLog(LogLevel::ERROR, "[socket : _handleClientSession] fail - Could not read username from socket " + std::to_string(client_socket));
    closeClient(client_socket);
    return;
  }
  std::string username(user_buf, bytes);
  writeLog(LogLevel::INFO, "[socket : _handleClientSession] Socket " + std::to_string(client_socket) + " is trying to login as '" + username + "'.");

  {
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (const auto& pair : active_clients) {
      if (pair.second == username) {
        writeLog(LogLevel::WARNING, "[socket : _handleClientSession] fail - Username '" + username + "' is already connected. Rejecting duplicate.");
        send(client_socket, "[Warning] Username already exists online.\n", 42,
             0);
        closeClient(client_socket);
        return;
      }
    }
  }

  std::string key_path = "keys/" + username + ".pem";
  uint32_t key_len_net = 0;
  if (recv(client_socket, &key_len_net, sizeof(key_len_net), MSG_WAITALL) <=
      0) {
    writeLog(LogLevel::ERROR, "[socket : _handleClientSession] fail - Failed to receive public key length from '" + username + "'.");
    closeClient(client_socket);
    return;
  }
  uint32_t key_len = ntohl(key_len_net);
  writeLog(LogLevel::INFO, "[socket : _handleClientSession] Expecting " + std::to_string(key_len) + " bytes of public key from '" + username + "'.");
  std::vector<char> key_buf(key_len);
  if (recv(client_socket, key_buf.data(), key_len, MSG_WAITALL) <= 0) {
    writeLog(LogLevel::ERROR, "[socket : _handleClientSession] fail - Failed to receive the actual public key payload from '" + username + "'.");
    closeClient(client_socket);
    return;
  }
  std::string client_pem(key_buf.begin(), key_buf.end());

  if (std::filesystem::exists(key_path)) {
    writeLog(LogLevel::INFO, "[socket : _handleClientSession] Key file exists for '" + username + "'. Checking if keys match...");
    std::ifstream kfile_in(key_path);
    std::stringstream ss;
    ss << kfile_in.rdbuf();
    if (ss.str() != client_pem) {
      writeLog(LogLevel::WARNING, "[socket : _handleClientSession] fail - Public key mismatch for registered user '" + username + "'. Denying access.");
      // Send failure notification so client doesn't hang silently
      std::string err_msg =
          "AUTH_FAIL: Username already registered with a different key "
          "(Unauthorized).\n";
      send(client_socket, err_msg.c_str(), err_msg.length(), 0);
      closeClient(client_socket);
      return;
    }
    writeLog(LogLevel::INFO, "[socket : _handleClientSession] Public key matches stored key for '" + username + "'.");
  } else {
    writeLog(LogLevel::INFO, "[socket : _handleClientSession] First time seeing '" + username + "'. Saving their public key to disk.");
    std::ofstream kfile(key_path);
    kfile << client_pem;
  }

  writeLog(LogLevel::INFO, "[socket : _handleClientSession] Initiating cryptographic challenge for '" + username + "'.");
  std::ifstream kfile_in(key_path);
  std::stringstream ss;
  ss << kfile_in.rdbuf();
  if (!Authenticator::authenticateClient(client_socket, ss.str())) {
    writeLog(LogLevel::ERROR, "[socket : _handleClientSession] fail - Cryptographic challenge failed for '" + username + "'. Sending packing.");
    // Send failure notification for cryptographic challenge failure
    std::string err_msg =
        "AUTH_FAIL: Private key verification failed (Access Denied).\n";
    send(client_socket, err_msg.c_str(), err_msg.length(), 0);
    closeClient(client_socket);
    return;
  }

  writeLog(LogLevel::INFO, "[socket : _handleClientSession] Handshake successful! User '" + username + "' is officially online.");
  send(client_socket, "HANDSHAKE_OK\n", 13, 0);

  {
    std::lock_guard<std::mutex> lock(clients_mutex);
    active_clients[client_socket] = username;
  }

  while (true) {
    std::string request = receiveData(client_socket);
    if (request.empty()) {
      writeLog(LogLevel::INFO, "[socket : _handleClientSession] Received empty request from '" + username + "'. Assuming they disconnected.");
      break;
    }

    if (request.rfind("PUB:", 0) == 0) {
      writeLog(LogLevel::INFO, "[socket : _handleClientSession] Received PUB request from '" + username + "'.");
      broadcastMessage(username, request.substr(4));
    } else if (request.rfind("PRV:", 0) == 0) {
      writeLog(LogLevel::INFO, "[socket : _handleClientSession] Received PRV direct message request from '" + username + "'.");
      size_t delimiter = request.find(':', 4);
      if (delimiter != std::string::npos) {
        sendDirectMessage(username, request.substr(4, delimiter - 4),
                          request.substr(delimiter + 1));
      } else {
        writeLog(LogLevel::WARNING, "[socket : _handleClientSession] fail - Malformed PRV request from '" + username + "'. Missing delimiter.");
      }
    } else if (request.rfind("FILE_OFFER:", 0) == 0) {
      writeLog(LogLevel::INFO, "[socket : _handleClientSession] User '" + username + "' is offering a file.");
      std::string sender = username;
      std::vector<std::string> recipients;
      std::string filename;
      size_t file_size = 0;

      if (transfer_manager.parseFileOffer(request, sender, recipients, filename,
                                          file_size)) {
        writeLog(LogLevel::INFO, "[socket : _handleClientSession] File offer parsed successfully: '" + filename + "' (" + std::to_string(file_size) + " bytes).");
        {
          std::lock_guard<std::mutex> lock(offers_map_mutex);
          pending_sender_offers[client_socket] = {recipients, file_size,
                                                  filename};
        }

        std::string notification = "[FILE_OFFER from " + sender +
                                   "]: " + filename + " (" +
                                   std::to_string(file_size) + " bytes)\n";

        {
          std::lock_guard<std::mutex> lock(clients_mutex);
          for (const auto& pair : active_clients) {
            if (std::find(recipients.begin(), recipients.end(), pair.second) !=
                recipients.end()) {
              send(pair.first, notification.c_str(), notification.length(), 0);
            }
          }
        }
      } else {
        writeLog(LogLevel::WARNING, "[socket : _handleClientSession] fail - Could not parse FILE_OFFER from '" + username + "'. Format might be broken.");
      }
    } else if (request.rfind("FILE_ACCEPT:", 0) == 0) {
      writeLog(LogLevel::INFO, "[socket : _handleClientSession] Received FILE_ACCEPT from '" + username + "'.");
      std::string target_sender_name = request.substr(12);
      int sender_socket = -1;
      ServerFileOffer offer;
      bool found = false;

      {
        std::lock_guard<std::mutex> lock(clients_mutex);
        for (const auto& pair : active_clients) {
          if (pair.second == target_sender_name) {
            sender_socket = pair.first;
            break;
          }
        }
      }

      if (sender_socket != -1) {
        std::lock_guard<std::mutex> lock(offers_map_mutex);
        auto it = pending_sender_offers.find(sender_socket);
        if (it != pending_sender_offers.end()) {
          offer = it->second;
          if (std::find(offer.recipients.begin(), offer.recipients.end(),
                        username) != offer.recipients.end()) {
            found = true;
          }
        }
      }

      if (found) {
        writeLog(LogLevel::INFO, "[socket : _handleClientSession] Matching file offer found for '" + target_sender_name + "'. Checking cache.");
        std::string cache_path =
            "uploads/" + target_sender_name + "_" + offer.filename;
        bool is_cached = false;
        {
          std::lock_guard<std::mutex> lock(active_uploads_mutex);
          if (std::filesystem::exists(cache_path) &&
              std::filesystem::file_size(cache_path) == offer.file_size) {
            is_cached = true;
          }
        }

        if (is_cached) {
          writeLog(LogLevel::INFO, "[socket : _handleClientSession] File '" + offer.filename + "' is already fully cached. Firing up a thread to push the cached file to '" + username + "'.");
          std::string cached_filename = offer.filename;
          size_t cached_size = offer.file_size;
          std::thread([this, client_socket, cache_path, cached_filename,
                       cached_size]() {
            std::ifstream file(cache_path, std::ios::binary);
            if (!file.is_open()) return;
            constexpr size_t CHUNK_SIZE = 65536;
            std::vector<char> buffer(CHUNK_SIZE);
            size_t sent = 0;
            while (sent < cached_size) {
              size_t to_read = std::min(CHUNK_SIZE, cached_size - sent);
              file.read(buffer.data(), to_read);
              std::streamsize n = file.gcount();
              if (n <= 0) break;
              std::string fwd_header = "FILE_CHUNK:" + cached_filename + ":" +
                                       std::to_string(n) + "\n";
              send(client_socket, fwd_header.c_str(), fwd_header.length(), 0);
              send(client_socket, buffer.data(), n, 0);
              sent += n;
            }
          }).detach();
        } else {
          writeLog(LogLevel::INFO, "[socket : _handleClientSession] File is not fully cached. Setting up upload trackers.");
          bool upload_in_progress = false;
          {
            std::lock_guard<std::mutex> lock(active_uploads_mutex);
            auto up_it = active_sender_uploads.find(sender_socket);
            if (up_it != active_sender_uploads.end()) {
              upload_in_progress = true;
              writeLog(LogLevel::INFO, "[socket : _handleClientSession] An upload for this file is already in progress. Adding '" + username + "' to pending cache recipients.");
              up_it->second.pending_cache_recipients.push_back(client_socket);
            }
          }

          if (!upload_in_progress) {
            writeLog(LogLevel::INFO, "[socket : _handleClientSession] Starting fresh upload tracking from sender socket " + std::to_string(sender_socket));
            {
              std::lock_guard<std::mutex> lock(active_uploads_mutex);
              active_sender_uploads[sender_socket] = ServerActiveUpload{
                  {username}, offer.file_size, offer.filename, 0, {}};
            }

            std::string temp_path =
                "uploads/temp_" + target_sender_name + "_" + offer.filename;
            std::ofstream ofs(temp_path, std::ios::binary | std::ios::trunc);

            writeLog(LogLevel::INFO, "[socket : _handleClientSession] Telling the sender we are ready for chunks.");
            std::string ready_msg = "READY_FOR_CHUNKS\n";
            send(sender_socket, ready_msg.c_str(), ready_msg.length(), 0);
          }
        }
      } else {
        writeLog(LogLevel::WARNING, "[socket : _handleClientSession] fail - Received FILE_ACCEPT but could not find a matching offer for '" + username + "'.");
      }
    } else if (request.rfind("FILE_UPLOAD:", 0) == 0) {
      ServerActiveUpload upload_info;
      bool has_active_upload = false;
      {
        std::lock_guard<std::mutex> lock(active_uploads_mutex);
        auto it = active_sender_uploads.find(client_socket);
        if (it != active_sender_uploads.end()) {
          upload_info = it->second;
          has_active_upload = true;
        }
      }

      if (has_active_upload) {
        size_t colon = request.rfind(':');
        if (colon != std::string::npos) {
          size_t chunk_size = std::stoull(request.substr(colon + 1));
          if (chunk_size > 0) {
            std::vector<char> chunk_buf(chunk_size);
            ssize_t bytes_read =
                recv(client_socket, chunk_buf.data(), chunk_size, MSG_WAITALL);
            if (bytes_read > 0) {
              std::string sender_name;
              {
                std::lock_guard<std::mutex> lock(clients_mutex);
                sender_name = active_clients[client_socket];
              }

              std::string temp_path =
                  "uploads/temp_" + sender_name + "_" + upload_info.filename;
              {
                std::ofstream cache_file(temp_path,
                                         std::ios::binary | std::ios::app);
                if (cache_file.is_open()) {
                  cache_file.write(chunk_buf.data(), bytes_read);
                }
              }

              std::vector<int> recipient_sockets;
              {
                std::lock_guard<std::mutex> lock(clients_mutex);
                for (const auto& pair : active_clients) {
                  if (std::find(upload_info.recipients.begin(),
                                upload_info.recipients.end(),
                                pair.second) != upload_info.recipients.end()) {
                    recipient_sockets.push_back(pair.first);
                  }
                }
              }

              std::string fwd_header = "FILE_CHUNK:" + upload_info.filename +
                                       ":" + std::to_string(bytes_read) + "\n";
              for (int client_sock : recipient_sockets) {
                if (!transfer_manager.isClientDropped(client_sock)) {
                  send(client_sock, fwd_header.c_str(), fwd_header.length(), 0);
                  send(client_sock, chunk_buf.data(), bytes_read, 0);
                }
              }

              {
                std::lock_guard<std::mutex> lock(active_uploads_mutex);
                auto it = active_sender_uploads.find(client_socket);
                if (it != active_sender_uploads.end()) {
                  it->second.bytes_received += bytes_read;
                  if (it->second.bytes_received >= it->second.file_size) {
                    writeLog(LogLevel::INFO, "[socket : _handleClientSession] Upload completed for '" + upload_info.filename + "'. Moving temp file to final destination.");
                    std::string final_path =
                        "uploads/" + sender_name + "_" + upload_info.filename;
                    std::filesystem::rename(temp_path, final_path);

                    for (int pending_sock :
                         it->second.pending_cache_recipients) {
                      writeLog(LogLevel::INFO, "[socket : _handleClientSession] Pushing newly cached file to pending recipient on socket " + std::to_string(pending_sock));
                      std::string cached_filename = upload_info.filename;
                      size_t cached_size = upload_info.file_size;
                      std::thread([this, pending_sock, final_path,
                                   cached_filename, cached_size]() {
                        std::ifstream file(final_path, std::ios::binary);
                        if (!file.is_open()) return;
                        constexpr size_t CHUNK_SIZE = 65536;
                        std::vector<char> buffer(CHUNK_SIZE);
                        size_t sent = 0;
                        while (sent < cached_size) {
                          size_t to_read =
                              std::min(CHUNK_SIZE, cached_size - sent);
                          file.read(buffer.data(), to_read);
                          std::streamsize n = file.gcount();
                          if (n <= 0) break;
                          std::string fwd_header =
                              "FILE_CHUNK:" + cached_filename + ":" +
                              std::to_string(n) + "\n";
                          send(pending_sock, fwd_header.c_str(),
                               fwd_header.length(), 0);
                          send(pending_sock, buffer.data(), n, 0);
                          sent += n;
                        }
                      }).detach();
                    }

                    active_sender_uploads.erase(it);
                  }
                }
              }
            } else {
              writeLog(LogLevel::ERROR, "[socket : _handleClientSession] fail - Dropped connection while trying to read file upload chunk.");
            }
          }
        } else {
          writeLog(LogLevel::WARNING, "[socket : _handleClientSession] fail - Malformed FILE_UPLOAD request (missing colon) from socket " + std::to_string(client_socket));
        }
      }
    } else if (request.rfind("FILE_REJECT:", 0) == 0) {
      writeLog(LogLevel::INFO, "[socket : _handleClientSession] User '" + username + "' is rejecting a file transfer.");
      std::string target_sender_name = request.substr(12);
      int sender_socket = -1;

      {
        std::lock_guard<std::mutex> lock(clients_mutex);
        for (const auto& pair : active_clients) {
          if (pair.second == target_sender_name) {
            sender_socket = pair.first;
            break;
          }
        }
      }

      if (sender_socket != -1) {
        writeLog(LogLevel::INFO, "[socket : _handleClientSession] Relaying rejection notice back to sender '" + target_sender_name + "'.");
        std::string rej_notice =
            "[Transfer] File offer rejected by " + username + ".\n";
        send(sender_socket, rej_notice.c_str(), rej_notice.length(), 0);
      } else {
        writeLog(LogLevel::WARNING, "[socket : _handleClientSession] Sender '" + target_sender_name + "' already disconnected, nowhere to send the rejection.");
      }
    } else if (request == "LIST") {
      writeLog(LogLevel::INFO, "[socket : _handleClientSession] Received LIST request from '" + username + "'. Sending active users.");
      std::string user_list = "[Server] Active users online:\n";
      {
        std::lock_guard<std::mutex> lock(clients_mutex);
        for (const auto& pair : active_clients) {
          user_list += "  - " + pair.second + "\n";
        }
      }
      send(client_socket, user_list.c_str(), user_list.length(), 0);
    } else {
      writeLog(LogLevel::WARNING, "[socket : _handleClientSession] Unrecognized command from '" + username + "': " + request.substr(0, 20) + "...");
    }
  }

  writeLog(LogLevel::INFO, "[socket : _handleClientSession] Session loop ended for user '" + username + "'. Cleaning up their records.");
  {
    std::lock_guard<std::mutex> lock(clients_mutex);
    active_clients.erase(client_socket);
  }
  {
    std::lock_guard<std::mutex> lock(offers_map_mutex);
    pending_sender_offers.erase(client_socket);
  }
  {
    std::lock_guard<std::mutex> lock(active_uploads_mutex);
    active_sender_uploads.erase(client_socket);
  }
  transfer_manager.removeClient(client_socket);
  closeClient(client_socket);
}

void TcpServer::start() {
  writeLog(LogLevel::INFO, "[socket : start] Setting up master socket...");
  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd == 0) _handleError("Failed to create master socket");

  int opt = 1;
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(port);

  writeLog(LogLevel::INFO, "[socket : start] Binding to port " + std::to_string(port) + "...");
  if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
    _handleError("Failed to bind port");
  }
  if (listen(server_fd, 128) < 0) {
    _handleError("Failed to listen");
  }
  
  writeLog(LogLevel::INFO, "[socket : start] Server is now fully listening. Ready for incoming connections.");

  while (true) {
    sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int client_socket =
        accept(server_fd, (struct sockaddr*)&client_addr, &addr_len);
    if (client_socket < 0) {
      writeLog(LogLevel::WARNING, "[socket : start] fail - Failed to accept a new client connection.");
      continue;
    }

    writeLog(LogLevel::INFO, "[socket : start] Accepted new connection on socket " + std::to_string(client_socket) + ". Spawning session handler thread.");
    std::thread(&TcpServer::_handleClientSession, this, client_socket).detach();
  }
}

std::string TcpServer::receiveData(int client_socket) {
  std::string line;
  char c;
  while (read(client_socket, &c, 1) > 0) {
    if (c == '\n') break;
    line += c;
  }
  return line;
}

void TcpServer::sendResponse(int client_socket, const std::string& resp) {
  writeLog(LogLevel::INFO, "[socket : sendResponse] Preparing payload for socket " + std::to_string(client_socket));
  std::string payload = resp + "\n";
  writeLog(LogLevel::INFO, "Sending response to socket " +
                               std::to_string(client_socket) + ": " + resp);
  send(client_socket, payload.c_str(), payload.length(), 0);
}

void TcpServer::closeClient(int client_socket) { 
  writeLog(LogLevel::INFO, "[socket : closeClient] Shutting down connection on socket " + std::to_string(client_socket));
  close(client_socket); 
}