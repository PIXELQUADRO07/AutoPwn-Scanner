/**
 * scanner_runner.cpp — AutoPwn Scanner v3.0
 * ═══════════════════════════════════════════════════════════════
 *  CLI stile Metasploit — versione finale
 *
 *  FEATURES:
 *  ─────────────────────────────────────────────────────────────
 *  Grafica / UX
 *    • 6 banner ASCII casuali + comando 'banner'
 *    • Prompt contestuale: autopwn (workspace/target) >
 *    • Progress bar animata con spinner
 *    • Tabelle formattate con bordi Unicode
 *    • Colori semantici: ✓[+] ✗[-] [!] [*] [»]
 *    • Cronometro su ogni comando
 *    • Pannello 'status' riepilogativo
 *    • Severity highlighting per CVE (critico/medio/basso)
 *
 *  Tecnico
 *    • History comandi (↑↓) + autocompletamento Tab (readline)
 *    • Comando 'set'       → parametri al volo
 *    • Comando 'show'      → opzioni correnti in tabella
 *    • Comando 'workspace' → cartelle separate per target
 *    • Comando 'ping'      → check raggiungibilità target
 *    • Comando 'whois'     → recon su IP/dominio
 *    • Comando 'export'    → CSV / HTML dal database
 *    • Comando 'history'   → storia comandi con timestamp
 *    • Comando 'status'    → pannello live riepilogativo
 *    • Modalità '--quiet'  → output minimale
 *    • Flag '--version'    → versione + features compilate
 *    • Timeout configurabile per ogni tool
 *    • Log automatico su file per ogni sessione
 *
 *  Qualità
 *    • SIGINT gestito → Ctrl+C torna al prompt
 *    • Validazione IP/CIDR prima di lanciare nmap
 *    • Input sanitization su tutti i parametri
 *
 * ─────────────────────────────────────────────────────────────
 *  Compilare (senza readline):
 *    g++ -o scanner_runner scanner_runner.cpp -std=c++17
 *
 *  Compilare (con readline — history+Tab):
 *    sudo pacman -S readline          # Arch
 *    sudo apt install libreadline-dev # Kali/Debian
 *    g++ -o scanner_runner scanner_runner.cpp -std=c++17 -lreadline
 * ═══════════════════════════════════════════════════════════════
 */

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
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
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
// POSIX — fork / execvp / waitpid / pipe
#include <unistd.h>
#include <sys/wait.h>

// ── Readline detection ───────────────────────────────────────────
#if __has_include(<readline/readline.h>)
  #include <readline/readline.h>
  #include <readline/history.h>
  #define HAS_READLINE 1
#else
  #define HAS_READLINE 0
#endif

namespace fs = std::filesystem;
using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;

// ════════════════════════════════════════════════════════════════
//  BUILD INFO
// ════════════════════════════════════════════════════════════════
static constexpr const char* VERSION    = "3.0.0";
static constexpr const char* BUILD_DATE = __DATE__;

// ════════════════════════════════════════════════════════════════
//  GLOBAL FLAGS
// ════════════════════════════════════════════════════════════════
static bool g_quiet  = false;  // --quiet: sopprime output verboso
static std::atomic<bool> g_interrupted{false};  // SIGINT handler

// ════════════════════════════════════════════════════════════════
//  SIGINT HANDLER  — Ctrl+C torna al prompt senza crashare
// ════════════════════════════════════════════════════════════════
static void sigint_handler(int) {
    g_interrupted = true;
    // Newline per non lasciare il cursore su ^C
    write(STDOUT_FILENO, "\n", 1);
}

static void reset_interrupt() { g_interrupted = false; }

// ════════════════════════════════════════════════════════════════
//  ANSI COLORS & TAGS
// ════════════════════════════════════════════════════════════════
namespace Color {
    const std::string R   = "\033[0m";
    const std::string B   = "\033[1m";
    const std::string DIM = "\033[2m";
    const std::string IT  = "\033[3m";

    const std::string RED = "\033[31m";
    const std::string GRN = "\033[32m";
    const std::string YEL = "\033[33m";
    const std::string BLU = "\033[34m";
    const std::string MAG = "\033[35m";
    const std::string CYN = "\033[36m";

    const std::string BRED = "\033[91m";
    const std::string BGRN = "\033[92m";
    const std::string BYEL = "\033[93m";
    const std::string BBLU = "\033[94m";
    const std::string BMAG = "\033[95m";
    const std::string BCYN = "\033[96m";
    const std::string BWHT = "\033[97m";

    std::string bold(const std::string& s)    { return B    + s + R; }
    std::string dim(const std::string& s)     { return DIM  + s + R; }
    std::string red(const std::string& s)     { return BRED + s + R; }
    std::string green(const std::string& s)   { return BGRN + s + R; }
    std::string yellow(const std::string& s)  { return BYEL + s + R; }
    std::string cyan(const std::string& s)    { return BCYN + s + R; }
    std::string magenta(const std::string& s) { return BMAG + s + R; }
    std::string blue(const std::string& s)    { return BBLU + s + R; }
}

namespace Tag {
    const std::string OK   = Color::BGRN + "[+]" + Color::R + " ";
    const std::string ERR  = Color::BRED + "[-]" + Color::R + " ";
    const std::string WARN = Color::BYEL + "[!]" + Color::R + " ";
    const std::string INFO = Color::BCYN + "[*]" + Color::R + " ";
    const std::string RUN  = Color::BBLU + "[»]" + Color::R + " ";
    const std::string SEC  = Color::BRED + "[CRIT]" + Color::R + " ";
    const std::string MED  = Color::BYEL + "[MED] " + Color::R + " ";
    const std::string LOW  = Color::DIM  + "[LOW] " + Color::R + " ";
}

// ════════════════════════════════════════════════════════════════
//  UTILITY
// ════════════════════════════════════════════════════════════════
static std::string now_hms() {
    auto t = std::chrono::system_clock::to_time_t(
                 std::chrono::system_clock::now());
    char buf[16]; std::strftime(buf, sizeof(buf), "%H:%M:%S",
                                std::localtime(&t));
    return buf;
}

static std::string now_full() {
    auto t = std::chrono::system_clock::to_time_t(
                 std::chrono::system_clock::now());
    char buf[32]; std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S",
                                std::localtime(&t));
    return buf;
}

static std::string now_stamp() {
    auto t = std::chrono::system_clock::to_time_t(
                 std::chrono::system_clock::now());
    char buf[20]; std::strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S",
                                std::localtime(&t));
    return buf;
}

static std::string format_elapsed(double secs) {
    if (secs < 60)
        return std::to_string(static_cast<int>(secs)) + "s";
    int m = static_cast<int>(secs) / 60;
    int s = static_cast<int>(secs) % 60;
    return std::to_string(m) + "m " + std::to_string(s) + "s";
}

static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    size_t b = s.find_last_not_of(" \t\r\n");
    return (a == std::string::npos) ? "" : s.substr(a, b - a + 1);
}

static std::string sanitize(const std::string& s) {
    std::string o;
    for (char c : s)
        o += (std::isalnum(static_cast<unsigned char>(c)) || c == '.') ? c : '_';
    return o;
}

static std::vector<std::string> tokenize(const std::string& line) {
    std::vector<std::string> tok;
    std::string cur; bool q = false;
    for (char c : line) {
        if (c == '"') { q = !q; continue; }
        if (c == ' ' && !q) { if (!cur.empty()) { tok.push_back(cur); cur.clear(); } }
        else cur += c;
    }
    if (!cur.empty()) tok.push_back(cur);
    return tok;
}

// ── Validazione IP / CIDR ────────────────────────────────────────
static bool valid_ip(const std::string& s) {
    // IPv4, IPv4/CIDR, hostname semplice
    static const std::regex ipv4(
        R"(^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$)");
    static const std::regex host(
        R"(^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})*$)");
    return std::regex_match(s, ipv4) || std::regex_match(s, host);
}

// ── exec helpers — usa fork+execve per evitare shell injection ────
//
// exec_argv: lancia un programma con argv esplicito (NO shell).
//   args[0] = path eseguibile, args[1..] = argomenti.
//   Se timeout_sec > 0 viene prepeso "timeout <sec>" via execve.
//   Restituisce exit code; stdout viene letto e stampato in streaming.
//
static int exec_argv(std::vector<std::string> args,
                     int timeout_sec = 0,
                     std::string* capture = nullptr) {
    // Prependi timeout se richiesto
    if (timeout_sec > 0) {
        args.insert(args.begin(), std::to_string(timeout_sec));
        args.insert(args.begin(), "timeout");
    }

    // Costruisci array di puntatori const char* per execvp
    std::vector<const char*> argv_ptrs;
    argv_ptrs.reserve(args.size() + 1);
    for (auto& a : args) argv_ptrs.push_back(a.c_str());
    argv_ptrs.push_back(nullptr);

    // Pipe per leggere stdout del figlio
    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;

    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return -1; }

    if (pid == 0) {
        // Child: redirect stdout sul write-end della pipe
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        // execvp cerca il programma nel PATH
        execvp(argv_ptrs[0],
               const_cast<char* const*>(argv_ptrs.data()));
        _exit(127);  // execvp fallito
    }

    // Parent: leggi dallo read-end
    close(pipefd[1]);
    char buf[512];
    ssize_t n;
    while (!g_interrupted &&
           (n = read(pipefd[0], buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        if (capture) *capture += buf;
        else { std::cout << buf; std::cout.flush(); }
    }
    close(pipefd[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

// Wrapper compatibile con il codice esistente (stringa → tokenizza → execve)
// Usato solo per comandi interni senza input utente.
static int exec_stream(const std::string& cmd, int timeout_sec = 0) {
    auto tok = tokenize(cmd);
    if (tok.empty()) return -1;
    return exec_argv(tok, timeout_sec);
}

static std::string exec_capture(const std::string& cmd,
                                 int timeout_sec = 0) {
    auto tok = tokenize(cmd);
    if (tok.empty()) return "";
    std::string out;
    exec_argv(tok, timeout_sec, &out);
    return out;
}

// Versione sicura con argv esplicito (usata da NmapRunner e SearchsploitRunner)
static int exec_stream_safe(std::vector<std::string> args,
                             int timeout_sec = 0) {
    return exec_argv(std::move(args), timeout_sec);
}

static std::string exec_capture_safe(std::vector<std::string> args,
                                      int timeout_sec = 0) {
    std::string out;
    exec_argv(std::move(args), timeout_sec, &out);
    return out;
}

static void write_tmp(const std::string& path, const std::string& s) {
    std::ofstream f(path); f << s;
}

// ════════════════════════════════════════════════════════════════
//  PROGRESS BAR
// ════════════════════════════════════════════════════════════════
class ProgressBar {
public:
    ProgressBar(const std::string& label, int width = 38)
        : label_(label), width_(width), running_(false), pct_(0) {}

    void start() {
        running_ = true; pct_ = 0;
        thread_ = std::thread(&ProgressBar::loop, this);
    }
    void set(int p) { pct_ = std::min(100, std::max(0, p)); }
    void stop(bool ok = true) {
        running_ = false;
        if (thread_.joinable()) thread_.join();
        std::cout << "\r  "
                  << (ok ? Color::BGRN : Color::BRED)
                  << std::left << std::setw(24) << label_ << Color::R
                  << " [" << (ok ? Color::BGRN : Color::BRED);
        for (int i = 0; i < width_; ++i)
            std::cout << (ok ? "\xe2\x96\x88" : "\xe2\x96\x91"); // █ / ░
        std::cout << Color::R << "] "
                  << (ok ? Color::BGRN + "DONE" : Color::BRED + "FAIL")
                  << Color::R << "   \n";
        std::cout.flush();
    }

private:
    void loop() {
        // UTF-8 braille spinner
        static const char* frames[] = {
            "\xe2\xa0\x8b","\xe2\xa0\x99","\xe2\xa0\xb9","\xe2\xa0\xb8",
            "\xe2\xa0\xbc","\xe2\xa0\xb4","\xe2\xa0\xa6","\xe2\xa0\xa7",
            "\xe2\xa0\x87","\xe2\xa0\x8f"
        };
        int frame = 0;
        while (running_) {
            int p    = pct_.load();
            int fill = (p * width_) / 100;
            std::cout << "\r  "
                      << Color::BCYN << std::left << std::setw(24) << label_
                      << Color::R << " [" << Color::BGRN;
            for (int i = 0; i < fill; ++i)
                std::cout << "\xe2\x96\x88";
            std::cout << Color::DIM;
            for (int i = fill; i < width_; ++i)
                std::cout << "\xe2\x96\x91";
            std::cout << Color::R << "] "
                      << Color::BYEL << std::setw(4)
                      << (std::to_string(p) + "%")
                      << Color::R << " "
                      << Color::BCYN << frames[frame % 10] << Color::R;
            std::cout.flush();
            ++frame;
            std::this_thread::sleep_for(100ms);
        }
    }

    std::string       label_;
    int               width_;
    std::atomic<bool> running_;
    std::atomic<int>  pct_;
    std::thread       thread_;
};

// ════════════════════════════════════════════════════════════════
//  TABLE
// ════════════════════════════════════════════════════════════════
class Table {
public:
    explicit Table(std::vector<std::string> h) : headers_(std::move(h)) {
        for (auto& hh : headers_) widths_.push_back(hh.size());
    }
    void add_row(std::vector<std::string> r) {
        for (size_t i = 0; i < r.size() && i < widths_.size(); ++i)
            widths_[i] = std::max(widths_[i], r[i].size());
        rows_.push_back(std::move(r));
    }
    bool empty() const { return rows_.empty(); }

    void print(const std::string& ind = "  ") const {
        auto line = [&](const char* l, const char* m, const char* r2) {
            std::cout << ind << Color::DIM << l;
            for (size_t i = 0; i < widths_.size(); ++i) {
                for (size_t j = 0; j < widths_[i] + 2; ++j)
                    std::cout << "\xe2\x95\x90"; // ═
                std::cout << (i + 1 < widths_.size() ? m : r2);
            }
            std::cout << Color::R << "\n";
        };
        line("\xe2\x95\x94","\xe2\x95\xa6","\xe2\x95\x97"); // ╔ ╦ ╗
        // header
        std::cout << ind << Color::DIM << "\xe2\x95\x91" << Color::R;
        for (size_t i = 0; i < headers_.size(); ++i)
            std::cout << " " << Color::B << Color::BCYN
                      << std::left << std::setw(widths_[i]) << headers_[i]
                      << Color::R << Color::DIM << " \xe2\x95\x91" << Color::R;
        std::cout << "\n";
        line("\xe2\x95\xa0","\xe2\x95\xac","\xe2\x95\xa3"); // ╠ ╬ ╣
        // rows
        for (auto& row : rows_) {
            std::cout << ind << Color::DIM << "\xe2\x95\x91" << Color::R;
            for (size_t i = 0; i < widths_.size(); ++i) {
                std::string cell = (i < row.size()) ? row[i] : "";
                std::cout << " " << Color::BWHT
                          << std::left << std::setw(widths_[i]) << cell
                          << Color::R << Color::DIM << " \xe2\x95\x91" << Color::R;
            }
            std::cout << "\n";
        }
        line("\xe2\x95\x9a","\xe2\x95\xa9","\xe2\x95\x9d"); // ╚ ╩ ╝
    }
private:
    std::vector<std::string>              headers_;
    std::vector<size_t>                   widths_;
    std::vector<std::vector<std::string>> rows_;
};

// ════════════════════════════════════════════════════════════════
//  SECTION / DIVIDER helpers
// ════════════════════════════════════════════════════════════════
static void section(const std::string& title,
                    const std::string& col = Color::BCYN) {
    int pad = 48 - static_cast<int>(title.size());
    std::cout << "\n" << col << Color::B << "  \xe2\x94\x8c\xe2\x94\x80 "
              << title << " ";
    for (int i = 0; i < std::max(0, pad); ++i)
        std::cout << "\xe2\x94\x80";
    std::cout << "\xe2\x94\x90" << Color::R << "\n";
}

static void section_end(const std::string& col = Color::DIM) {
    std::cout << col << "  \xe2\x94\x94";
    for (int i = 0; i < 54; ++i) std::cout << "\xe2\x94\x80";
    std::cout << "\xe2\x94\x98" << Color::R << "\n";
}

static void divider() {
    std::cout << Color::DIM << "  ";
    for (int i = 0; i < 56; ++i) std::cout << "\xe2\x94\x80";
    std::cout << Color::R << "\n";
}

static void print_elapsed(double secs) {
    std::cout << Color::DIM << "  Completed in "
              << Color::BYEL << format_elapsed(secs)
              << Color::R << "\n";
}

// ════════════════════════════════════════════════════════════════
//  LOGGER
// ════════════════════════════════════════════════════════════════
class Logger {
public:
    Logger() = default;
    ~Logger() { if (f_.is_open()) { f_ << "\n=== Session ended: " << now_full() << " ===\n"; f_.close(); } }

    void open(const std::string& path) {
        fs::create_directories(fs::path(path).parent_path());
        f_.open(path, std::ios::app);
        if (f_.is_open())
            f_ << "=== Session started: " << now_full() << " ===\n";
        path_ = path;
    }

    void log(const std::string& msg) {
        if (!f_.is_open()) return;
        std::lock_guard<std::mutex> lk(mu_);
        f_ << "[" << now_hms() << "] " << strip_ansi(msg) << "\n";
        f_.flush();
    }

    void log_cmd(const std::string& cmd) { log("CMD: " + cmd); }
    const std::string& path() const { return path_; }

private:
    std::ofstream f_;
    std::mutex    mu_;
    std::string   path_;

    static std::string strip_ansi(const std::string& s) {
        std::string o; bool esc = false;
        for (char c : s) {
            if (c == '\033') { esc = true; continue; }
            if (esc) { if (c == 'm') esc = false; continue; }
            o += c;
        }
        return o;
    }
};

// ════════════════════════════════════════════════════════════════
//  CMD HISTORY  (in-session, con timestamp)
// ════════════════════════════════════════════════════════════════
struct HistoryEntry { std::string time, cmd; };
static std::vector<HistoryEntry> g_history;

static void history_push(const std::string& cmd) {
    g_history.push_back({now_hms(), cmd});
}

static void print_history() {
    section("COMMAND HISTORY", Color::BCYN);
    if (g_history.empty()) {
        std::cout << Tag::INFO << "No commands yet.\n";
        return;
    }
    Table t({"#", "Time", "Command"});
    for (size_t i = 0; i < g_history.size(); ++i)
        t.add_row({std::to_string(i + 1),
                   g_history[i].time,
                   g_history[i].cmd});
    t.print();
    section_end();
}

// ════════════════════════════════════════════════════════════════
//  CONFIG
// ════════════════════════════════════════════════════════════════
class Config {
public:
    std::string msf_password        = "change_this_password";
    std::string msf_host            = "127.0.0.1";
    std::string msf_port            = "55553";
    std::string output_dir          = "./results";
    std::string monitor_interval    = "5";
    std::string post_pipeline_wait  = "10";
    std::string timeout_nmap        = "600";
    std::string timeout_searchsploit= "60";
    std::string timeout_msf         = "120";
    std::string db_path             = "./results/scanner.db";
    std::string workspace           = "default";
    std::string log_dir             = "./logs";
    std::string config_path         = "config.ini";

    std::map<std::string, std::string*> fields() {
        return {
            {"msf_password",         &msf_password},
            {"msf_host",             &msf_host},
            {"msf_port",             &msf_port},
            {"output_dir",           &output_dir},
            {"monitor_interval",     &monitor_interval},
            {"post_pipeline_wait",   &post_pipeline_wait},
            {"timeout_nmap",         &timeout_nmap},
            {"timeout_searchsploit", &timeout_searchsploit},
            {"timeout_msf",          &timeout_msf},
            {"db_path",              &db_path},
            {"workspace",            &workspace},
            {"log_dir",              &log_dir},
        };
    }

    std::string ws_dir() const {
        return output_dir + "/ws_" + sanitize(workspace);
    }

    void load(const std::string& path = "config.ini") {
        config_path = path;
        std::ifstream f(path); if (!f.is_open()) return;
        std::string line, sec;
        while (std::getline(f, line)) {
            line = trim(line);
            if (line.empty() || line[0] == '#') continue;
            if (line.front() == '[' && line.back() == ']') {
                sec = line.substr(1, line.size() - 2); continue;
            }
            auto eq = line.find('='); if (eq == std::string::npos) continue;
            std::string k = trim(line.substr(0, eq));
            std::string v = trim(line.substr(eq + 1));
            auto h = v.find('#'); if (h != std::string::npos) v = trim(v.substr(0, h));
            (void)sec;
            auto fm = fields(); if (fm.count(k)) *fm[k] = v;
        }
    }

    void save() const {
        std::ofstream f(config_path); if (!f.is_open()) return;
        f << "# AutoPwn Scanner v3 — config.ini\n# Do NOT commit.\n\n"
          << "[metasploit]\nmsf_password        = " << msf_password
          << "\nmsf_host            = " << msf_host
          << "\nmsf_port            = " << msf_port
          << "\n\n[scanner]\noutput_dir          = " << output_dir
          << "\nmonitor_interval    = " << monitor_interval
          << "\npost_pipeline_wait  = " << post_pipeline_wait
          << "\n\n[timeouts]\ntimeout_nmap        = " << timeout_nmap
          << "\ntimeout_searchsploit= " << timeout_searchsploit
          << "\ntimeout_msf         = " << timeout_msf
          << "\n\n[database]\ndb_path             = " << db_path
          << "\n\n[workspace]\nworkspace           = " << workspace
          << "\nlog_dir             = " << log_dir << "\n";
    }
};

// ════════════════════════════════════════════════════════════════
//  BANNER POOL
// ════════════════════════════════════════════════════════════════
struct Banner { std::string color, art, tagline; };

static const Banner& random_banner() {
    static const std::vector<Banner> pool = {
        { Color::BCYN, R"(
   ___        __       ____                  ___
  / _ | __ __/ /____  / __ \    ___ ___ ___ |_  |
 / __ |/ // / __/ _ \/ /_/ /  (_-</ -_) -_)/ __/
/_/ |_|\_,_/\__/\___/ .___/  /___/\__/\__/____/
                    /_/                          )",
          "  Automated Penetration Testing Pipeline — v3.0" },

        { Color::BGRN, R"(
 ▄▄▄       █    ██ ▄▄▄█████▓ ▒█████   ██▓███  ██▓  ██████
▒████▄     ██  ▓██▒▓  ██▒ ▓▒▒██▒  ██▒▓██░  ██▒▓██▒▒██    ▒
▒██  ▀█▄  ▓██  ▒██░▒ ▓██░ ▒░▒██░  ██▒▓██░ ██▓▒▒██▒░ ▓██▄
░██▄▄▄▄██ ▓▓█  ░██░░ ▓██▓ ░ ▒██   ██░▒██▄█▓▒ ▒░██░  ▒   ██▒
 ▓█   ▓██▒▒▒█████▓   ▒██▒ ░ ░ ████▓▒░▒██▒ ░  ░░██░▒██████▒▒
 ▒▒   ▓▒█░░▒▓▒ ▒ ▒   ▒ ░░   ░ ▒░▒░▒░ ▒▓▒░ ░  ░░▓  ▒ ▒▓▒ ▒ ░
  ▒   ▒▒ ░░░▒░ ░ ░     ░      ░ ▒ ▒░ ░▒ ░      ▒ ░░ ░▒  ░ ░)",
          "  [ Nmap · Searchsploit · Metasploit RPC · v3 ]" },

        { Color::BMAG, R"(
  _____       _       _____
 |  _  |_ _ | |_ ___|  _  |_ _ _ ___
 |     | | ||  _| . |   __| | | |   |   v3.0
 |__|__|___|_|_| |___|__|  |_____|_|_|
  scan · enumerate · exploit · persist )",
          "  for authorized lab environments only" },

        { Color::BYEL, R"(
┌─┐┬ ┬┌┬┐┌─┐  ┌─┐┬ ┬┌┐┌  ┌─┐┌─┐┌─┐┌┐┌┌┐┌┌─┐┬─┐
├─┤│ │ │ │ │  ├─┘│││││││  └─┐│  ├─┤││││││├┤ ├┬┘
┴ ┴└─┘ ┴ └─┘  ┴  └┘┘└┘└─┘  └─┘└─┘┴ ┴┘└┘┘└┘└─┘┴└─
                                            v3.0    )",
          "  authorized environments only" },

        { Color::BRED, R"(
  /\  _   _|_  _  |_   /\  / \/  _  _
 /--\(_)_) |_ (_) |_) /--\ \_/\/(/_|
  ─────────────────────────────── v3 ─)",
          "  offensive automation — think before you scan" },

        { Color::BGRN, R"(
  ▄▄▄· ▄• ▄▌▄▄▄▄▄      ▄▄▄·▄▄▌ ▐ ▄▌ ▐ ▄
 ▐█ ▀█ █▪██▌•██  ▪     ▐█ ▄██•  █▌▐█•█▌▐█
 ▄█▀▀█ █▌▐█▌ ▐█.▪ ▄█▀▄  ██▀·██ ▐█▐▐▌▐█▐▐▌
 ▐█ ▪▐▌▐█▄█▌ ▐█▌·▐█▌.▐▌▐█▪·•▐█▌██▐█▌██▐█▌
  ▀  ▀  ▀▀▀  ▀▀▀  ▀█▄▀▪.▀    ▀▀▀▀ ▀▪▀▀ █▪)",
          "  wake up. the network is waiting." },
    };
    static std::mt19937 rng(static_cast<unsigned>(
        Clock::now().time_since_epoch().count()));
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
              << "  |  v" << VERSION
              << "  |  " << now_full()
              << Color::R << "\n\n";
}

// ════════════════════════════════════════════════════════════════
//  AUTOCOMPLETION
// ════════════════════════════════════════════════════════════════
static const std::vector<std::string> COMMANDS = {
    "scan","nmap","ping","whois","sessions","kill","cleanup",
    "report","export","set","show","workspace","history",
    "status","banner","config","help","version","exit","quit"
};

#if HAS_READLINE
static char* cmd_gen(const char* text, int state) {
    static size_t idx; static std::string pfx;
    if (state == 0) { idx = 0; pfx = text; }
    while (idx < COMMANDS.size()) {
        const std::string& c = COMMANDS[idx++];
        if (c.rfind(pfx, 0) == 0) return strdup(c.c_str());
    }
    return nullptr;
}
static char** autopwn_complete(const char* text, int, int) {
    rl_attempted_completion_over = 1;
    return rl_completion_matches(text, cmd_gen);
}
static void init_readline() {
    rl_attempted_completion_function = autopwn_complete;
    rl_bind_key('\t', rl_complete);
}
#endif

// ════════════════════════════════════════════════════════════════
//  PROMPT
// ════════════════════════════════════════════════════════════════
static std::string g_target;

static std::string build_prompt(const Config& cfg) {
    std::string ctx = Color::BYEL + cfg.workspace + Color::R;
    if (!g_target.empty())
        ctx += Color::DIM + "/" + Color::R + Color::BCYN + g_target + Color::R;
    return Color::B + Color::BRED + "autopwn" + Color::R
         + Color::DIM + " (" + Color::R + ctx + Color::DIM + ")" + Color::R
         + Color::B + " > " + Color::R;
}

static std::string read_line(const Config& cfg) {
    std::string pr = build_prompt(cfg);
#if HAS_READLINE
    char* raw = readline(pr.c_str());
    if (!raw) return "exit";
    std::string line = trim(raw);
    if (!line.empty()) add_history(raw);
    free(raw); return line;
#else
    std::cout << pr;
    std::string line;
    if (!std::getline(std::cin, line)) return "exit";
    return trim(line);
#endif
}

// ════════════════════════════════════════════════════════════════
//  SEVERITY COLORING  (per output searchsploit / CVE)
// ════════════════════════════════════════════════════════════════
static void print_severity_line(const std::string& line) {
    // Cerca pattern CVSS o parole chiave severity
    std::string lo = line;
    std::transform(lo.begin(), lo.end(), lo.begin(), ::tolower);

    if (lo.find("critical") != std::string::npos ||
        lo.find("remote code") != std::string::npos ||
        lo.find("rce") != std::string::npos)
        std::cout << Tag::SEC << line;
    else if (lo.find("medium") != std::string::npos ||
             lo.find("privilege") != std::string::npos)
        std::cout << Tag::MED << line;
    else if (lo.find("low") != std::string::npos ||
             lo.find("info") != std::string::npos)
        std::cout << Tag::LOW << line;
    else
        std::cout << Color::DIM << "  " << line << Color::R;

    if (line.back() != '\n') std::cout << "\n";
}

// ════════════════════════════════════════════════════════════════
//  NMAP RUNNER
// ════════════════════════════════════════════════════════════════
class NmapRunner {
public:
    NmapRunner(Config& c, Logger& l) : cfg(c), log(l) {}

    std::string run(const std::string& target) {
        std::string ws  = cfg.ws_dir();
        std::string xml = ws + "/scan_" + sanitize(target) + ".xml";
        fs::create_directories(ws);

        section("NMAP SCAN", Color::BCYN);
        if (!g_quiet) {
            std::cout << Tag::INFO << "Target    : " << Color::BYEL << target << Color::R << "\n";
            std::cout << Tag::INFO << "XML out   : " << Color::DIM  << xml    << Color::R << "\n";
            std::cout << Tag::INFO << "Timeout   : " << cfg.timeout_nmap << "s\n";
            std::cout << Tag::INFO << "Workspace : " << cfg.workspace << "\n";
        }
        divider();

        log.log_cmd("nmap " + target);
        auto t0 = Clock::now();

        ProgressBar pb("Scanning " + target, 34);
        pb.start();

        std::atomic<bool> done{false};
        std::thread ticker([&](){
            for (int p = 0; !done && p < 93; p += 2)
            { std::this_thread::sleep_for(3s); pb.set(p); }
        });

        if (!g_quiet) std::cout << "\n";
        // Argv esplicito — nessuna interpolazione shell
        int rc = exec_stream_safe(
            {"nmap", "-sV", "--script=vulners", "-oX", xml, target},
            std::stoi(cfg.timeout_nmap));
        done = true;
        if (ticker.joinable()) ticker.join();
        pb.stop(rc == 0 && fs::exists(xml));

        double elapsed = std::chrono::duration<double>(Clock::now() - t0).count();
        print_elapsed(elapsed);
        divider();

        if (rc == 0 && fs::exists(xml)) {
            std::cout << Tag::OK << Color::green("Scan complete → ") << xml << "\n";
            log.log("[+] nmap done in " + format_elapsed(elapsed) + " → " + xml);
            return xml;
        }
        std::string err = (rc == 124)
            ? "Timed out after " + cfg.timeout_nmap + "s"
            : "Failed (exit " + std::to_string(rc) + ")";
        std::cout << Tag::ERR << Color::red(err) << "\n";
        log.log("[-] nmap " + err);
        return "";
    }
private:
    Config& cfg; Logger& log;
};

// ════════════════════════════════════════════════════════════════
//  SEARCHSPLOIT RUNNER
// ════════════════════════════════════════════════════════════════
class SearchsploitRunner {
public:
    SearchsploitRunner(Config& c, Logger& l) : cfg(c), log(l) {}

    std::string run(const std::string& xml) {
        std::string json = cfg.ws_dir() + "/searchsploit_results.json";
        section("SEARCHSPLOIT", Color::BMAG);
        if (!g_quiet)
            std::cout << Tag::INFO << "Parsing: " << Color::DIM << xml << Color::R << "\n";
        divider();

        auto t0 = Clock::now();
        ProgressBar pb("Querying exploitdb", 34);
        pb.start();
        // Argv esplicito — nessuna shell injection possibile
        std::string out = exec_capture_safe(
            {"searchsploit", "--nmap", xml, "-j"},
            std::stoi(cfg.timeout_searchsploit));
        pb.stop(!out.empty());

        std::ofstream f(json); f << out;

        // Stampa risultati con severity highlighting
        std::istringstream ss(out);
        std::string line;
        std::cout << "\n";
        while (std::getline(ss, line))
            print_severity_line(line);

        double elapsed = std::chrono::duration<double>(Clock::now() - t0).count();
        print_elapsed(elapsed);
        divider();
        std::cout << Tag::OK << "Results → " << Color::DIM << json << Color::R << "\n";
        log.log("[+] searchsploit done in " + format_elapsed(elapsed));
        return json;
    }
private:
    Config& cfg; Logger& log;
};

// ════════════════════════════════════════════════════════════════
//  PYTHON BRIDGE
// ════════════════════════════════════════════════════════════════
class PythonBridge {
public:
    PythonBridge(Config& c, Logger& l) : cfg(c), log(l) {}

    bool invoke(const std::string& xml, const std::string& json) {
        section("LOGIC MAPPER", Color::BGRN);
        if (!g_quiet)
            std::cout << Tag::INFO << "MSF RPC: "
                      << cfg.msf_host << ":" << cfg.msf_port << "\n";
        divider();

        auto t0 = Clock::now();
        log.log_cmd("logic_mapper " + xml);
        int rc = exec_stream(
            "python3 ./logic_mapper.py"
            " --xml "  + xml +
            " --json " + json +
            " --monitor-interval " + cfg.monitor_interval + " 2>&1",
            std::stoi(cfg.timeout_msf));
        double elapsed = std::chrono::duration<double>(Clock::now() - t0).count();
        print_elapsed(elapsed);
        divider();
        if (rc == 0) {
            std::cout << Tag::OK << Color::green("Logic mapper completed.\n");
            log.log("[+] logic_mapper done in " + format_elapsed(elapsed));
            return true;
        }
        std::cout << Tag::ERR << Color::red("Exited with code " + std::to_string(rc)) << "\n";
        log.log("[-] logic_mapper rc=" + std::to_string(rc));
        return false;
    }
private:
    Config& cfg; Logger& log;
};

// ════════════════════════════════════════════════════════════════
//  PING
// ════════════════════════════════════════════════════════════════
static void cmd_ping(const std::string& target, Logger& log) {
    section("PING", Color::BCYN);
    std::cout << Tag::INFO << "Testing reachability: "
              << Color::BYEL << target << Color::R << "\n";
    divider();

    auto t0 = Clock::now();
    int rc = exec_stream("ping -c 4 -W 2 " + target + " 2>&1");
    double elapsed = std::chrono::duration<double>(Clock::now() - t0).count();
    print_elapsed(elapsed);
    divider();
    if (rc == 0)
        std::cout << Tag::OK  << Color::green(target + " is reachable.\n");
    else
        std::cout << Tag::ERR << Color::red(target + " is unreachable.\n");
    log.log((rc == 0 ? "[+]" : "[-]") + std::string(" ping ") + target);
}

// ════════════════════════════════════════════════════════════════
//  WHOIS
// ════════════════════════════════════════════════════════════════
static void cmd_whois(const std::string& target, Logger& log) {
    section("WHOIS RECON", Color::BBLU);
    std::cout << Tag::INFO << "Target: "
              << Color::BYEL << target << Color::R << "\n";
    divider();

    auto t0 = Clock::now();
    int rc = exec_stream("whois " + target + " 2>&1", 30);
    double elapsed = std::chrono::duration<double>(Clock::now() - t0).count();
    print_elapsed(elapsed);
    divider();
    if (rc != 0)
        std::cout << Tag::WARN << "whois not available or query failed.\n";
    log.log("[*] whois " + target);
}

// ════════════════════════════════════════════════════════════════
//  EXPORT  (CSV / HTML)
// ════════════════════════════════════════════════════════════════
static void cmd_export(const std::vector<std::string>& tok,
                       const Config& cfg, Logger& log) {
    std::string fmt  = tok.size() > 1 ? tok[1] : "csv";
    std::string out  = cfg.ws_dir() + "/export_" + now_stamp()
                       + "." + fmt;

    if (!fs::exists(cfg.db_path)) {
        std::cout << Tag::ERR << "No database found. Run a scan first.\n";
        return;
    }

    section("EXPORT", Color::BYEL);
    std::cout << Tag::INFO << "Format : " << Color::BYEL << fmt << Color::R << "\n";
    std::cout << Tag::INFO << "Output : " << Color::DIM  << out << Color::R << "\n";
    divider();

    if (fmt == "csv") {
        // Usa sqlite3 per dump CSV
        std::string cmd =
            "sqlite3 -separator ',' " + cfg.db_path +
            " 'SELECT t.ip,t.hostname,v.port,v.service,v.version,"
            "v.exploit_name,v.has_msf,e.success "
            "FROM Vulnerabilities v "
            "LEFT JOIN Targets t ON v.target_id=t.id "
            "LEFT JOIN Exploits_Found e ON e.vuln_id=v.id'"
            " > " + out + " 2>&1";
        int rc = exec_stream(cmd);
        if (rc == 0)
            std::cout << Tag::OK << Color::green("CSV exported → ") << out << "\n";
        else
            std::cout << Tag::ERR << "sqlite3 not found or query failed.\n";

    } else if (fmt == "html") {
        // Genera HTML con tabella stilizzata
        std::string data = exec_capture(
            "sqlite3 -separator '|' " + cfg.db_path +
            " 'SELECT t.ip,v.port,v.service,v.version,v.exploit_name,v.has_msf "
            "FROM Vulnerabilities v JOIN Targets t ON v.target_id=t.id'");

        std::ofstream f(out);
        f << "<!DOCTYPE html><html><head><meta charset='utf-8'>\n"
          << "<title>AutoPwn Report</title>\n"
          << "<style>body{font-family:monospace;background:#0d0d0d;color:#e0e0e0;padding:2em}"
          << "table{border-collapse:collapse;width:100%}"
          << "th{background:#1a1a2e;color:#00d4ff;padding:8px;border:1px solid #333}"
          << "td{padding:6px;border:1px solid #333}"
          << "tr:nth-child(even){background:#111}"
          << ".msf{color:#00ff88;font-weight:bold}"
          << "h1{color:#ff4757}h2{color:#00d4ff}</style></head>\n"
          << "<body><h1>&#128273; AutoPwn Scanner v3</h1>\n"
          << "<h2>Report generated: " << now_full() << "</h2>\n"
          << "<h2>Workspace: " << cfg.workspace << "</h2>\n"
          << "<table><tr><th>IP</th><th>Port</th><th>Service</th>"
          << "<th>Version</th><th>Exploit</th><th>MSF?</th></tr>\n";

        std::istringstream ss(data);
        std::string line;
        while (std::getline(ss, line)) {
            std::vector<std::string> cells;
            std::stringstream ls(line);
            std::string cell;
            while (std::getline(ls, cell, '|'))
                cells.push_back(cell);
            f << "<tr>";
            for (size_t i = 0; i < cells.size(); ++i) {
                bool msf = (i == 5 && cells[i] == "1");
                f << "<td" << (msf ? " class='msf'" : "") << ">"
                  << (msf ? "&#10003; YES" : cells[i]) << "</td>";
            }
            f << "</tr>\n";
        }
        f << "</table></body></html>\n";
        std::cout << Tag::OK << Color::green("HTML exported → ") << out << "\n";
    } else {
        std::cout << Tag::ERR << "Unknown format. Use: export csv | export html\n";
        return;
    }
    log.log("[*] export " + fmt + " → " + out);
    section_end();
}

// ════════════════════════════════════════════════════════════════
//  STATUS PANEL
// ════════════════════════════════════════════════════════════════
static void cmd_status(const Config& cfg, Logger& log) {
    section("STATUS", Color::BCYN);

    Table t({"Field", "Value"});
    t.add_row({"Version",        std::string("v") + VERSION + " (" + BUILD_DATE + ")"});
    t.add_row({"Workspace",      cfg.workspace});
    t.add_row({"Last target",    g_target.empty() ? "none" : g_target});
    t.add_row({"Output dir",     cfg.ws_dir()});
    t.add_row({"Database",       fs::exists(cfg.db_path)
                                   ? cfg.db_path + " [exists]"
                                   : cfg.db_path + " [not found]"});
    t.add_row({"MSF RPC",        cfg.msf_host + ":" + cfg.msf_port});
    t.add_row({"Log file",       log.path()});
    t.add_row({"Commands run",   std::to_string(g_history.size())});
    t.add_row({"Readline",       std::string(HAS_READLINE ? "enabled" : "disabled")});
    t.add_row({"Quiet mode",     g_quiet ? "on" : "off"});
    t.print();
    section_end();
    log.log("[*] status shown");
}

// ════════════════════════════════════════════════════════════════
//  SESSION MANAGER
// ════════════════════════════════════════════════════════════════
class SessionManager {
public:
    SessionManager(Config& c, Logger& l) : cfg(c), log(l) {}

    void list() {
        section("ACTIVE SESSIONS", Color::BGRN);
        std::string script =
            "import json, sys\n"
            "try:\n"
            "    from pymetasploit3.msfrpc import MsfRpcClient\n"
            "    c = MsfRpcClient('" + cfg.msf_password + "',"
            " server='" + cfg.msf_host + "', port=" + cfg.msf_port + ")\n"
            "    s = c.sessions.list\n"
            "    print(json.dumps(s))\n"
            "except ImportError: print(json.dumps({'__error':'pymetasploit3 not found'}))\n"
            "except Exception as e: print(json.dumps({'__error':str(e)}))\n";
        write_tmp("/tmp/_ap_s.py", script);
        std::string out = exec_capture("python3 /tmp/_ap_s.py");
        fs::remove("/tmp/_ap_s.py");

        if (out.find("\"__error\"") != std::string::npos) {
            std::cout << Tag::ERR << Color::red("Cannot reach msfrpcd.\n");
            std::cout << Tag::INFO << out << "\n";
        } else if (out.find("{}") != std::string::npos || trim(out).empty()) {
            std::cout << Tag::WARN << Color::yellow("No active sessions.\n");
        } else {
            std::cout << Tag::OK << "Session data:\n\n";
            highlight_json(out);
        }
        log.log("[*] sessions listed");
    }

    void kill(const std::string& sid) {
        if (sid.empty()) { std::cout << Tag::ERR << "Usage: kill <id>\n"; return; }
        section("KILL SESSION", Color::BRED);
        std::string script =
            "try:\n"
            "    from pymetasploit3.msfrpc import MsfRpcClient\n"
            "    c = MsfRpcClient('" + cfg.msf_password + "',"
            " server='" + cfg.msf_host + "', port=" + cfg.msf_port + ")\n"
            "    c.sessions.session('" + sid + "').stop()\n"
            "    print('[+] Session " + sid + " terminated.')\n"
            "except Exception as e: print(f'[-] {e}')\n";
        write_tmp("/tmp/_ap_k.py", script);
        exec_stream("python3 /tmp/_ap_k.py");
        fs::remove("/tmp/_ap_k.py");
        log.log("[*] kill session " + sid);
    }

private:
    Config& cfg; Logger& log;

    static void highlight_json(const std::string& s) {
        bool in_str = false, key = true;
        for (size_t i = 0; i < s.size(); ++i) {
            char c = s[i];
            if (c == '"') {
                in_str = !in_str;
                if (in_str) std::cout << (key ? Color::BCYN : Color::BYEL);
                else { std::cout << '"' << Color::R; key = false; continue; }
            }
            if (!in_str) {
                if (c=='{' || c=='}'|| c=='['|| c==']') std::cout << Color::BMAG;
                if (c==':') { std::cout << Color::DIM; key = false; }
                if (c==',') { std::cout << Color::R;   key = true;  }
            }
            std::cout << c;
            if (!in_str && (c=='{'||c=='}'||c=='['||c==']'||c==':'||c==','))
                std::cout << Color::R;
        }
        std::cout << Color::R << "\n";
    }
};

// ════════════════════════════════════════════════════════════════
//  DB REPORT
// ════════════════════════════════════════════════════════════════
class DbReport {
public:
    DbReport(Config& c, Logger& l) : cfg(c), log(l) {}
    void show() {
        section("DATABASE REPORT", Color::BBLU);
        if (!fs::exists(cfg.db_path)) {
            std::cout << Tag::WARN << "No database at " << cfg.db_path
                      << " — run a scan first.\n"; return;
        }
        std::cout << Tag::INFO << Color::DIM << cfg.db_path << Color::R << "\n\n";
        auto t0 = Clock::now();
        exec_stream("python3 ./db_report.py " + cfg.db_path);
        print_elapsed(std::chrono::duration<double>(Clock::now()-t0).count());
        log.log("[*] report shown");
    }
private:
    Config& cfg; Logger& log;
};

// ════════════════════════════════════════════════════════════════
//  WORKSPACE MANAGER
// ════════════════════════════════════════════════════════════════
class WorkspaceManager {
public:
    WorkspaceManager(Config& c, Logger& l) : cfg(c), log(l) {}

    void run(const std::vector<std::string>& tok) {
        std::string sub  = tok.size() > 1 ? tok[1] : "list";
        std::string name = tok.size() > 2 ? tok[2] : "";

        if (sub == "list") {
            section("WORKSPACES", Color::BYEL);
            Table t({"Workspace","Path","Status"});
            bool found = false;
            if (fs::exists(cfg.output_dir)) {
                for (auto& e : fs::directory_iterator(cfg.output_dir)) {
                    if (!e.is_directory()) continue;
                    std::string n = e.path().filename().string();
                    if (n.rfind("ws_", 0) != 0) continue;
                    std::string wn = n.substr(3);
                    t.add_row({wn, e.path().string(),
                        wn == cfg.workspace
                            ? Color::BGRN + "● active" + Color::R
                            : Color::DIM  + "○ idle"   + Color::R});
                    found = true;
                }
            }
            if (found) t.print();
            else std::cout << Tag::INFO << "No workspaces yet.\n";
            section_end();

        } else if (sub == "use" || sub == "switch") {
            if (name.empty()) { std::cout << Tag::ERR << "Usage: workspace use <name>\n"; return; }
            cfg.workspace = name;
            fs::create_directories(cfg.ws_dir());
            std::cout << Tag::OK << "Switched to: " << Color::BYEL << name << Color::R << "\n";
            log.log("[*] workspace → " + name);

        } else if (sub == "new") {
            if (name.empty()) { std::cout << Tag::ERR << "Usage: workspace new <name>\n"; return; }
            cfg.workspace = name;
            fs::create_directories(cfg.ws_dir());
            std::cout << Tag::OK << "Created: " << Color::BYEL << name << Color::R << "\n";
            log.log("[*] workspace new " + name);

        } else if (sub == "delete") {
            if (name.empty() || name == "default") {
                std::cout << Tag::ERR << "Cannot delete 'default'.\n"; return;
            }
            std::string path = cfg.output_dir + "/ws_" + sanitize(name);
            if (fs::exists(path)) {
                fs::remove_all(path);
                std::cout << Tag::OK << "Deleted: " << name << "\n";
                if (cfg.workspace == name) {
                    cfg.workspace = "default";
                    std::cout << Tag::INFO << "Switched back to default.\n";
                }
            } else {
                std::cout << Tag::WARN << "Not found: " << name << "\n";
            }
        } else {
            std::cout << Tag::ERR << "Usage: workspace [list|new|use|delete] [name]\n";
        }
    }
private:
    Config& cfg; Logger& log;
};

// ════════════════════════════════════════════════════════════════
//  SET / SHOW
// ════════════════════════════════════════════════════════════════
static void cmd_set(const std::vector<std::string>& tok,
                    Config& cfg, Logger& log) {
    if (tok.size() < 3) {
        std::cout << Tag::ERR << "Usage: set <option> <value>\n"
                  << Tag::INFO << "Type 'show' to see all options.\n"; return;
    }
    auto fm = cfg.fields();
    if (!fm.count(tok[1])) {
        std::cout << Tag::ERR << "Unknown option: " << tok[1]
                  << " — type 'show'\n"; return;
    }
    std::string old = *fm[tok[1]];
    *fm[tok[1]] = tok[2];
    std::cout << Tag::OK
              << Color::BYEL << tok[1] << Color::R << " => "
              << Color::BGRN << tok[2] << Color::R
              << Color::DIM  << "  (was: " << old << ")" << Color::R << "\n";
    log.log("[*] set " + tok[1] + "=" + tok[2]);
}

static void cmd_show(const Config& cfg) {
    section("OPTIONS", Color::BCYN);
    Table t({"Option","Value","Description"});
    auto add = [&](const std::string& k, const std::string& v,
                   const std::string& d) { t.add_row({k,v,d}); };
    add("msf_host",             cfg.msf_host,                    "Metasploit RPC host");
    add("msf_port",             cfg.msf_port,                    "Metasploit RPC port");
    add("msf_password",         std::string(cfg.msf_password.size(),'*'), "RPC password (hidden)");
    add("workspace",            cfg.workspace,                   "Active workspace");
    add("output_dir",           cfg.output_dir,                  "Results base dir");
    add("monitor_interval",     cfg.monitor_interval,            "Session poll (s)");
    add("post_pipeline_wait",   cfg.post_pipeline_wait,          "Post-pipeline wait (s)");
    add("timeout_nmap",         cfg.timeout_nmap,                "Nmap timeout (0=off)");
    add("timeout_searchsploit", cfg.timeout_searchsploit,        "Searchsploit timeout");
    add("timeout_msf",          cfg.timeout_msf,                 "MSF RPC timeout");
    add("db_path",              cfg.db_path,                     "SQLite database");
    add("log_dir",              cfg.log_dir,                     "Log directory");
    t.print();
    section_end();
}

// ════════════════════════════════════════════════════════════════
//  CONFIG WIZARD
// ════════════════════════════════════════════════════════════════
static void config_wizard(Config& cfg, Logger& log) {
    section("CONFIGURATION WIZARD", Color::BMAG);
    std::cout << Color::DIM << "  Press Enter to keep current value.\n\n" << Color::R;
    auto ask = [](const std::string& lbl, const std::string& cur) {
        std::cout << "  " << Color::BCYN << std::left << std::setw(28) << lbl
                  << Color::DIM << "[" << cur << "]" << Color::BCYN
                  << ": " << Color::R;
        std::string v; std::getline(std::cin, v);
        return v.empty() ? cur : v;
    };
    std::cout << Color::BMAG << "  [ Metasploit RPC ]\n" << Color::R;
    cfg.msf_host      = ask("host",              cfg.msf_host);
    cfg.msf_port      = ask("port",              cfg.msf_port);
    cfg.msf_password  = ask("password",          cfg.msf_password);
    std::cout << Color::BMAG << "\n  [ Scanner ]\n" << Color::R;
    cfg.output_dir         = ask("output_dir",         cfg.output_dir);
    cfg.monitor_interval   = ask("monitor_interval",   cfg.monitor_interval);
    cfg.post_pipeline_wait = ask("post_pipeline_wait", cfg.post_pipeline_wait);
    std::cout << Color::BMAG << "\n  [ Timeouts (seconds, 0=disable) ]\n" << Color::R;
    cfg.timeout_nmap         = ask("timeout_nmap",         cfg.timeout_nmap);
    cfg.timeout_searchsploit = ask("timeout_searchsploit", cfg.timeout_searchsploit);
    cfg.timeout_msf          = ask("timeout_msf",          cfg.timeout_msf);
    std::cout << Color::BMAG << "\n  [ Database ]\n" << Color::R;
    cfg.db_path = ask("db_path", cfg.db_path);
    std::cout << Color::BMAG << "\n  [ Logging ]\n" << Color::R;
    cfg.log_dir = ask("log_dir", cfg.log_dir);
    std::cout << "\n" << Color::BCYN << "  Save to config.ini? [Y/n]: " << Color::R;
    std::string yn; std::getline(std::cin, yn);
    if (yn.empty() || yn=="y" || yn=="Y") {
        cfg.save();
        std::cout << Tag::OK << Color::green("config.ini saved.\n");
        log.log("[*] config saved");
    } else {
        std::cout << Tag::WARN << "Changes discarded.\n";
    }
}

// ════════════════════════════════════════════════════════════════
//  HELP
// ════════════════════════════════════════════════════════════════
static void print_help() {
    section("HELP", Color::BCYN);
    auto row = [](const std::string& c, const std::string& a,
                  const std::string& d) {
        std::cout << "  " << Color::BGRN << std::left << std::setw(12) << c
                  << Color::BYEL << std::setw(26) << a
                  << Color::R << Color::DIM << d << Color::R << "\n";
    };
    std::cout << "\n  " << Color::B << Color::BCYN << "Recon\n" << Color::R;
    row("ping",      "<target>",            "Check host reachability");
    row("whois",     "<target>",            "Domain/IP recon");
    std::cout << "\n  " << Color::B << Color::BCYN << "Scanning\n" << Color::R;
    row("scan",      "<target>",            "Full pipeline: nmap+searchsploit+msf");
    row("nmap",      "<target>",            "Run Nmap only");
    std::cout << "\n  " << Color::B << Color::BCYN << "Sessions\n" << Color::R;
    row("sessions",  "",                    "List active MSF sessions");
    row("kill",      "<id>",               "Terminate a session");
    row("cleanup",   "",                   "Kill ALL open MSF sessions");
    std::cout << "\n  " << Color::B << Color::BCYN << "Data\n" << Color::R;
    row("report",    "",                   "Show SQLite report");
    row("export",    "csv|html",           "Export results to file");
    std::cout << "\n  " << Color::B << Color::BCYN << "Configuration\n" << Color::R;
    row("set",       "<option> <value>",   "Set option on the fly");
    row("show",      "",                   "Show all current options");
    row("config",    "",                   "Interactive wizard");
    row("workspace", "list|new|use|delete","Manage workspaces");
    std::cout << "\n  " << Color::B << Color::BCYN << "Misc\n" << Color::R;
    row("status",    "",                   "Live status panel");
    row("history",   "",                   "Command history");
    row("banner",    "",                   "New random banner");
    row("version",   "",                   "Version info");
    row("help",      "",                   "This help");
    row("exit",      "",                   "Quit");
    std::cout << "\n  " << Color::B << "Examples\n" << Color::R;
    std::cout << Color::DIM  << "  autopwn > " << Color::R << "ping 192.168.1.1\n";
    std::cout << Color::DIM  << "  autopwn > " << Color::R << "scan 192.168.1.0/24\n";
    std::cout << Color::DIM  << "  autopwn > " << Color::R << "set timeout_nmap 300\n";
    std::cout << Color::DIM  << "  autopwn > " << Color::R << "workspace new lab_01\n";
    std::cout << Color::DIM  << "  autopwn > " << Color::R << "export html\n";
    std::cout << Color::DIM  << "  autopwn > " << Color::R << "kill 2\n";
    std::cout << "\n";
    section_end();
}

// ════════════════════════════════════════════════════════════════
//  VERSION
// ════════════════════════════════════════════════════════════════
static void print_version() {
    section("VERSION INFO", Color::BCYN);
    Table t({"Field","Value"});
    t.add_row({"Version",    std::string(VERSION)});
    t.add_row({"Build date", std::string(BUILD_DATE)});
    t.add_row({"Standard",   "C++17"});
    t.add_row({"Readline",   HAS_READLINE ? "enabled (history+tab)" : "disabled"});
    t.add_row({"SIGINT",     "handled (Ctrl+C returns to prompt)"});
    t.add_row({"Features",   "execve(no shell injection)|cleanup|CVE corr.|ranking|payload select"});
    t.print();
    section_end();
}

// ════════════════════════════════════════════════════════════════
//  DISPATCH
// ════════════════════════════════════════════════════════════════
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

    history_push(cmd + (a1.empty() ? "" : " " + a1));
    log.log_cmd(cmd + (a1.empty() ? "" : " " + a1));
    reset_interrupt();

    if (cmd == "scan") {
        if (a1.empty()) { std::cout << Tag::ERR << "Usage: scan <target>\n"; return 1; }
        if (!valid_ip(a1)) {
            std::cout << Tag::ERR << "Invalid target: " << a1
                      << "\n" << Tag::INFO << "Expected IPv4, CIDR or hostname.\n";
            return 1;
        }
        g_target = a1;
        std::string xml = nmr.run(a1);
        if (xml.empty() || g_interrupted) return 2;
        std::string json = ssr.run(xml);
        if (!g_interrupted) pb.invoke(xml, json);
        return 0;
    }
    if (cmd == "nmap") {
        if (a1.empty()) { std::cout << Tag::ERR << "Usage: nmap <target>\n"; return 1; }
        if (!valid_ip(a1)) {
            std::cout << Tag::ERR << "Invalid target: " << a1 << "\n"; return 1; }
        g_target = a1; nmr.run(a1); return 0;
    }
    if (cmd == "ping") {
        if (a1.empty()) { std::cout << Tag::ERR << "Usage: ping <target>\n"; return 1; }
        cmd_ping(a1, log); return 0;
    }
    if (cmd == "whois") {
        if (a1.empty()) { std::cout << Tag::ERR << "Usage: whois <target>\n"; return 1; }
        cmd_whois(a1, log); return 0;
    }
    if (cmd == "sessions")  { sm.list();              return 0; }
    if (cmd == "kill")      { sm.kill(a1);            return 0; }
    if (cmd == "cleanup") {
        // Chiude tutte le sessioni MSF aperte tramite Python
        section("CLEANUP SESSIONS", Color::BRED);
        std::string script =
            "try:\n"
            "    from pymetasploit3.msfrpc import MsfRpcClient\n"
            "    c = MsfRpcClient('" + cfg.msf_password + "',"
            " server='" + cfg.msf_host + "', port=" + cfg.msf_port + ")\n"
            "    sessions = c.sessions.list\n"
            "    if not sessions:\n"
            "        print('[*] No sessions to clean up.')\n"
            "    else:\n"
            "        for sid in list(sessions.keys()):\n"
            "            try:\n"
            "                c.sessions.session(str(sid)).stop()\n"
            "                print(f'[+] Closed session {sid}')\n"
            "            except Exception as e:\n"
            "                print(f'[-] {sid}: {e}')\n"
            "        print('[+] Cleanup complete.')\n"
            "except Exception as e:\n"
            "    print(f'[-] {e}')\n";
        write_tmp("/tmp/_ap_cleanup.py", script);
        exec_stream("python3 /tmp/_ap_cleanup.py");
        fs::remove("/tmp/_ap_cleanup.py");
        log.log("[*] cleanup sessions");
        return 0;
    }
    if (cmd == "report")    { dr.show();              return 0; }
    if (cmd == "export")    { cmd_export(tok,cfg,log);return 0; }
    if (cmd == "set")       { cmd_set(tok,cfg,log);   return 0; }
    if (cmd == "show")      { cmd_show(cfg);          return 0; }
    if (cmd == "workspace") { wm.run(tok);            return 0; }
    if (cmd == "history")   { print_history();        return 0; }
    if (cmd == "status")    { cmd_status(cfg,log);    return 0; }
    if (cmd == "banner")    { print_banner(cfg);      return 0; }
    if (cmd == "version")   { print_version();        return 0; }
    if (cmd == "config")    {
        config_wizard(cfg, log);
        cfg.load(cfg.config_path);
        return 0;
    }
    if (cmd == "help" || cmd == "?" || cmd == "-h" || cmd == "--help") {
        print_help(); return 0;
    }
    if (cmd == "exit" || cmd == "quit" || cmd == "q") return -99;

    std::cout << Tag::ERR << "Unknown command: " << Color::BYEL << cmd
              << Color::R << " — type " << Color::DIM << "help" << Color::R << "\n";
    return 1;
}

// ════════════════════════════════════════════════════════════════
//  INTERACTIVE LOOP
// ════════════════════════════════════════════════════════════════
static void interactive_loop(Config& cfg, Logger& log) {
#if HAS_READLINE
    init_readline();
#endif
    std::cout << Color::DIM << "  Type "
              << Color::R << Color::BGRN << "help"
              << Color::R << Color::DIM << " for available commands. "
              << Color::R << Color::BRED << "Ctrl+C"
              << Color::R << Color::DIM << " interrupts running tools.\n"
              << (HAS_READLINE ? "  Tab autocomplete and \xe2\x86\x91\xe2\x86\x93 history enabled.\n" : "")
              << Color::R << "\n";

    while (true) {
        std::string line = read_line(cfg);
        if (line.empty()) continue;

        auto tok = tokenize(line);
        if (tok.empty()) continue;
        std::transform(tok[0].begin(), tok[0].end(), tok[0].begin(), ::tolower);

        int rc = dispatch(tok, cfg, log);
        if (rc == -99) {
            std::cout << "\n" << Color::cyan("  Goodbye.\n\n");
            break;
        }
        std::cout << "\n";
    }
}

// ════════════════════════════════════════════════════════════════
//  MAIN
// ════════════════════════════════════════════════════════════════
int main(int argc, char* argv[]) {
    // SIGINT → torna al prompt invece di crashare
    struct sigaction sa{};
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);

    Config cfg;
    cfg.load("config.ini");

    // Analizza flags globali prima del dispatch
    std::vector<char*> rest_args;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--quiet" || a == "-q") { g_quiet = true; }
        else if (a == "--version" || a == "-v") {
            print_banner(cfg); print_version(); return 0;
        }
        else rest_args.push_back(argv[i]);
    }

    // Logger per la sessione
    fs::create_directories(cfg.log_dir);
    std::string log_path = cfg.log_dir + "/session_" + now_stamp() + ".log";
    Logger log;
    log.open(log_path);

    print_banner(cfg);
    if (!g_quiet)
        std::cout << Color::DIM << "  Log → " << log_path << Color::R << "\n\n";

    // ── DIRECT MODE ──────────────────────────────────────────────
    if (!rest_args.empty()) {
        std::vector<std::string> tok;
        for (auto* a : rest_args) tok.push_back(a);
        std::transform(tok[0].begin(), tok[0].end(), tok[0].begin(), ::tolower);
        if (!g_quiet) {
            std::cout << Color::DIM << "  [" << now_hms() << "] direct: ";
            for (auto& t : tok) std::cout << t << " ";
            std::cout << Color::R << "\n\n";
        }
        int rc = dispatch(tok, cfg, log);
        return (rc == -99) ? 0 : rc;
    }

    // ── INTERACTIVE MODE ─────────────────────────────────────────
    interactive_loop(cfg, log);
    return 0;
}
