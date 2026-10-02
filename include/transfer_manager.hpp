#pragma once

#include <atomic>
#include <mutex>
#include <queue>
#include <string>
#include <unordered_map>
#include <vector>

// Buffer structure to hold outbound chunks for slow consumer handling
struct ClientTransferBuffer {
  std::queue<std::vector<char>> outbound_queue;
  size_t current_bytes_queued = 0;
  size_t high_water_mark = 2 * 1024 * 1024;  // Default fallback: 2 MB
  bool is_dropped = false;
};

// Manager to handle file transfer queueing, parsing, and backpressure
// protection
class FileTransferManager {
 public:
  explicit FileTransferManager(size_t high_water_mark = 2 * 1024 * 1024);
  ~FileTransferManager() = default;

  // Parses incoming file offer requests (FILE_OFFER:[recipients]:size:filename)
  bool parseFileOffer(const std::string& request, std::string& out_sender,
                      std::vector<std::string>& out_recipients,
                      std::string& out_filename, size_t& out_filesize);

  // Enqueues file chunks for specific clients with backpressure check
  bool enqueueChunkForClient(int client_socket, const char* data,
                             size_t length);

  // Flushes pending chunks for the client socket
  bool flushClientQueue(int client_socket);

  // Checks if a client has been dropped due to slow consumption
  bool isClientDropped(int client_socket);

  // Removes client from tracking when disconnected
  void removeClient(int client_socket);

 private:
  std::mutex manager_mutex;
  std::unordered_map<int, ClientTransferBuffer> client_buffers;
  size_t global_high_water_mark;
};