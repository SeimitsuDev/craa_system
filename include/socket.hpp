#pragma once

#include <netinet/in.h>

#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "transfer_manager.hpp"

// Structure to track pending server-side offers awaiting acceptance/rejection
struct ServerFileOffer {
  std::vector<std::string> recipients;
  size_t file_size;
  std::string filename;
};

// Structure to track active server-side uploads handled by sender session
struct ServerActiveUpload {
  std::vector<std::string> recipients;
  size_t file_size;
  std::string filename;
  size_t bytes_received = 0;
  std::vector<int> pending_cache_recipients;  // Added globally to fix type resolution
};

// Singleton TCP Server class handling client connections, authentication, chat, and file transfers
class TcpServer {
 private:
  int server_fd;
  int port;
  std::string server_password;
  sockaddr_in address;

  // We are using 3 mutext for each respective Data Structure listed below
  std::mutex clients_mutex;
  std::unordered_map<int, std::string> active_clients;

  std::mutex offers_map_mutex;
  std::unordered_map<int, ServerFileOffer> pending_sender_offers;

  std::mutex active_uploads_mutex;
  std::unordered_map<int, ServerActiveUpload> active_sender_uploads;

  // high water is the caution stoping the sender for a while before overflow
  explicit TcpServer(int port, std::string password, size_t high_water_mark);
  ~TcpServer();

  void _handleError(const std::string& message);
  void _handleClientSession(int client_socket);

  // For public message
  void broadcastMessage(const std::string& sender, const std::string& message);

  // For private message
  void sendDirectMessage(const std::string& sender,
                         const std::string& recipient,
                         const std::string& message);

  // To send file through nerwork
  void handleFileStreamBroadcast(int sender_socket,
                                 const std::vector<std::string>& recipients,
                                 size_t file_size, const std::string& filename);

 public:

  // All compiler default constructors are delete by suing this
  TcpServer(const TcpServer&) = delete;
  TcpServer& operator=(const TcpServer&) = delete;

  // Access singleton instance of the TCP server
  static TcpServer& getSocketObject(int port = 8080,
                                    const std::string& password = "",
                                    size_t high_water_mark = 2 * 1024 * 1024) {
    static TcpServer instance(port, password, high_water_mark);
    return instance;
  }

  // These three functions provides the utility to send and receive messages and close the server
  std::string receiveData(int client_socket);
  void sendResponse(int client_socket, const std::string& response);
  void closeClient(int client_socket);
  
  // Transfer manager is useful for the queue of all the tranfering files from the server which is useful and need for this project
  FileTransferManager transfer_manager;

  // This functions will used to start the server
  void start();
};