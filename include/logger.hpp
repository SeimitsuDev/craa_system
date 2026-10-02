#pragma once

#include <chrono>
#include <iomanip>
#include <iostream>
#include <string>

enum class LogLevel { INFO, WARNING, ERROR };

inline void writeLog(LogLevel level, const std::string& message) {
  // To turn off DEBUG MODE
#ifdef DEBUG_MODE
  auto now = std::chrono::system_clock::now();
  auto in_time_t = std::chrono::system_clock::to_time_t(now);

  std::string level_str;
  std::ostream& out_stream = (level == LogLevel::ERROR) ? std::cerr : std::cout;

  switch (level) {
    case LogLevel::INFO:
      level_str = "INFO";
      break;
    case LogLevel::WARNING:
      level_str = "WARNING";
      break;
    case LogLevel::ERROR:
      level_str = "ERROR";
      break;
  }

  out_stream << "["
             << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %H:%M:%S")
             << "] "
             << "[" << level_str << "] " << message << std::endl;
#endif
}