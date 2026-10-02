#include <algorithm>
#include <exception>
#include <iostream>
#include <string>

#include "logger.hpp"
#include "socket.hpp"

// This function is to display the correct command usage instructions
void printUsage(const char* prog_name) {
  std::cerr << "Invalid command syntax.\n\n"
            << "Correct usage:\n"
            << "  " << prog_name << " [password] [-p | --port <port number>]\n"
            << "  " << prog_name
            << " [-p | --port <port number>] [password]\n\n"
            << "Examples:\n"
            << "  " << prog_name << " MySecurePassword1234 -p 9090\n"
            << "  " << prog_name << " --port 8080 MyPassword1234\n"
            << "  " << prog_name
            << " (uses default password '1234' and port 8080)\n";
}

int main(int argc, char* argv[]) {
  // Defaults
  int port = 8080;
  std::string server_password = "1234";

  // Parse command-line arguments
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];

    if (arg == "-p" || arg == "--port") {
      if (i + 1 < argc) {
        try {
          port = std::stoi(argv[i + 1]);
          i++;  // Skip the port number value
        } catch (...) {
          std::cerr << "[Error] Invalid port number format.\n\n";
          printUsage(argv[0]);
          return 1;
        }
      } else {
        std::cerr << "[Error] Missing port number value after " << arg
                  << "\n\n";
        printUsage(argv[0]);
        return 1;
      }
    } else if (arg[0] == '-') {
      std::cerr << "[Error] Unknown option: " << arg << "\n\n";
      printUsage(argv[0]);
      return 1;
    } else {
      // Positional argument interpreted as the server password
      server_password = arg;
    }
  }

  std::cout << "[Server] Initializing secure multi-user chat server..."
            << std::endl;
  std::cout << "[Server] Port set to: " << port << std::endl;
  std::cout << "[Server] Access Password set to: " << server_password
            << std::endl;

  try {
    // Singleton object of the TcpServer
    TcpServer& server = TcpServer::getSocketObject(port, server_password);

    // Start the continuous multi-threaded listener loop
    server.start();

  } catch (const std::exception& e) {
    writeLog(LogLevel::ERROR,
             "[Main] Fatal server exception: " + std::string(e.what()));
    std::cerr << "Fatal error: " << e.what() << std::endl;
    return 1;
  }

  return 0;
}