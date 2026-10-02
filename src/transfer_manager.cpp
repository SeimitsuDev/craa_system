#include "transfer_manager.hpp"
#include "logger.hpp"

#include <sys/socket.h>

#include <algorithm>
#include <sstream>

// Constructor initializing global high watermark for backpressure
FileTransferManager::FileTransferManager(size_t high_water_mark)
    : global_high_water_mark(high_water_mark > 0 ? high_water_mark
                                                 : 2 * 1024 * 1024) {
  writeLog(LogLevel::INFO, "[transfer_manager] FileTransferManager initialized with high watermark: " + std::to_string(global_high_water_mark) + " bytes.");
}

// Parses the path-based or standard file offer request
bool FileTransferManager::parseFileOffer(
    const std::string& request, std::string& out_sender,
    std::vector<std::string>& out_recipients, std::string& out_filename,
    size_t& out_filesize) {
  writeLog(LogLevel::INFO, "[transfer_manager]Attempting to parse file offer request.");
  
  if (request.rfind("FILE_OFFER:", 0) != 0) {
    writeLog(LogLevel::WARNING, "[transfer_manager : parseFileOffer] fail - Request does not start with FILE_OFFER:");
    return false;
  }

  size_t bracket_start = request.find('[');
  size_t bracket_end = request.find(']');
  if (bracket_start == std::string::npos || bracket_end == std::string::npos) {
    writeLog(LogLevel::WARNING, "[transfer_manager : parseFileOffer] fail - Missing recipient brackets [].");
    return false;
  }

  std::string list_str =
      request.substr(bracket_start + 1, bracket_end - bracket_start - 1);
  std::stringstream ss(list_str);
  std::string recipient;
  while (std::getline(ss, recipient, ',')) {
    recipient.erase(0, recipient.find_first_not_of(" \t"));
    recipient.erase(recipient.find_last_not_of(" \t") + 1);
    if (!recipient.empty()) {
      out_recipients.push_back(recipient);
      writeLog(LogLevel::INFO, "[transfer_manager : parseFileOffer] Found recipient - " + recipient);
    }
  }

  size_t size_delim = request.find(':', bracket_end);
  if (size_delim == std::string::npos) {
    writeLog(LogLevel::WARNING, "[transfer_manager : parseFileOffer] fail - Missing size delimiter.");
    return false;
  }

  size_t filename_delim = request.find(':', size_delim + 1);
  if (filename_delim == std::string::npos) {
    writeLog(LogLevel::WARNING, "[transfer_manager : parseFileOffer] fail - Missing filename delimiter.");
    return false;
  }

  try {
    out_filesize = std::stoull(
        request.substr(size_delim + 1, filename_delim - size_delim - 1));
    writeLog(LogLevel::INFO, "[transfer_manager : parseFileOffer] Parsed file size - " + std::to_string(out_filesize) + " bytes.");
  } catch (const std::exception& e) {
    writeLog(LogLevel::ERROR, std::string("[transfer_manager : parseFileOffer] fail - Exception parsing file size - ") + e.what());
    return false;
  } catch (...) {
    writeLog(LogLevel::ERROR, "[transfer_manager : parseFileOffer] fail - Unknown exception parsing file size.");
    return false;
  }

  out_filename = request.substr(filename_delim + 1);
  writeLog(LogLevel::INFO, "[transfer_manager : parseFileOffer] Parsed filename - " + out_filename);
  
  if (out_recipients.empty() || out_filename.empty()) {
    writeLog(LogLevel::WARNING, "[transfer_manager : parseFileOffer] fail - Recipients list or filename is empty after parsing.");
    return false;
  }
  
  writeLog(LogLevel::INFO, "[transfer_manager : parseFileOffer] fail - Successfully parsed file offer.");
  return true;
}

// Enqueues data chunks for a target client socket with backpressure check
bool FileTransferManager::enqueueChunkForClient(int client_socket,
                                                const char* data,
                                                size_t length) {
  writeLog(LogLevel::INFO, "[transfer_manager] Attempting to enqueue " + std::to_string(length) + " bytes for socket " + std::to_string(client_socket));
  std::lock_guard<std::mutex> lock(manager_mutex);
  auto& buf = client_buffers[client_socket];

  if (buf.high_water_mark == 2 * 1024 * 1024 &&
      global_high_water_mark != (2 * 1024 * 1024)) {
    writeLog(LogLevel::INFO, "[transfer_manager] Adjusting high watermark for socket " + std::to_string(client_socket) + " to global limit: " + std::to_string(global_high_water_mark));
    buf.high_water_mark = global_high_water_mark;
  }

  if (buf.is_dropped) {
    writeLog(LogLevel::WARNING, "[transfer_manager : enqueueChunkForClient] Socket " + std::to_string(client_socket) + " is marked as dropped. Discarding chunk.");
    return false;
  }

  // Slow consumer backpressure check: drop client if buffer exceeds high watermark
  if (buf.current_bytes_queued + length > buf.high_water_mark) {
    writeLog(LogLevel::ERROR, "[transfer_manager : enqueueChunkForClient] fail - Backpressure triggered for socket " + std::to_string(client_socket) + 
                              ". Queue size (" + std::to_string(buf.current_bytes_queued + length) + 
                              ") exceeds watermark (" + std::to_string(buf.high_water_mark) + "). Dropping client.");
    buf.is_dropped = true;
    return false;
  }

  buf.outbound_queue.push(std::vector<char>(data, data + length));
  buf.current_bytes_queued += length;
  writeLog(LogLevel::INFO, "[transfer_manager : enqueueChunkForClient] Successfully queued chunk. Current queue size for socket " + std::to_string(client_socket) + " is " + std::to_string(buf.current_bytes_queued) + " bytes.");
  return true;
}

// Flushes queued data chunks to the client socket
bool FileTransferManager::flushClientQueue(int client_socket) {
  writeLog(LogLevel::INFO, "Flushing client queue for socket " + std::to_string(client_socket));
  std::lock_guard<std::mutex> lock(manager_mutex);
  auto it = client_buffers.find(client_socket);
  if (it == client_buffers.end()) {
    writeLog(LogLevel::WARNING, "[transfer_manager : flushClientQueue] No buffer found for socket " + std::to_string(client_socket));
    return false;
  }
  if (it->second.is_dropped) {
    writeLog(LogLevel::WARNING, "[transfer_manager : flushClientQueue] Socket " + std::to_string(client_socket) + " is dropped. Aborting flush.");
    return false;
  }

  auto& buf = it->second;
  int chunks_sent = 0;
  while (!buf.outbound_queue.empty()) {
    const auto& chunk = buf.outbound_queue.front();
    ssize_t sent =
        send(client_socket, chunk.data(), chunk.size(), MSG_NOSIGNAL);
    if (sent < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        writeLog(LogLevel::INFO, "[transfer_manager : flushClientQueue] Socket " + std::to_string(client_socket) + " would block. Pausing flush.");
        break;
      }
      writeLog(LogLevel::ERROR, "[transfer_manager : flushClientQueue] fail - Socket " + std::to_string(client_socket) + " encountered network error during send. Dropping client.");
      buf.is_dropped = true;
      return false;
    }
    buf.current_bytes_queued -= chunk.size();
    buf.outbound_queue.pop();
    chunks_sent++;
  }
  
  writeLog(LogLevel::INFO, "[transfer_manager : flushClientQueue] Sent " + std::to_string(chunks_sent) + " chunks for socket " + std::to_string(client_socket) + ". Remaining queue size: " + std::to_string(buf.current_bytes_queued) + " bytes.");
  return true;
}

// Checks whether a client is dropped due to queue congestion
bool FileTransferManager::isClientDropped(int client_socket) {
  std::lock_guard<std::mutex> lock(manager_mutex);
  auto it = client_buffers.find(client_socket);
  if (it != client_buffers.end()) {
    return it->second.is_dropped;
  }
  return false;
}

// Cleans up tracking for disconnected clients
void FileTransferManager::removeClient(int client_socket) {
  writeLog(LogLevel::INFO, "[transfer_manager] Cleaning up buffers for socket " + std::to_string(client_socket));
  std::lock_guard<std::mutex> lock(manager_mutex);
  client_buffers.erase(client_socket);
}