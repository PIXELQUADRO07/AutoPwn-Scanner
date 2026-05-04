/**
 * scanner_runner.cpp
 * Esegue Nmap e Searchsploit e comunica con il logic-mapper Python.
 * Compilare con: g++ -o scanner_runner scanner_runner.cpp -std=c++17
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <filesystem>
#include <chrono>
#include <ctime>

namespace fs = std::filesystem;

// ─────────────────────────────────────────────
// Utility: esegue un comando e ne cattura stdout
// ─────────────────────────────────────────────
std::string exec_command(const std::string& cmd) {
    std::string result;
    char buffer[256];

    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        throw std::runtime_error("popen() fallito per: " + cmd);
    }

    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }

    int exit_code = pclose(pipe);
    if (exit_code != 0) {
        std::cerr << "[WARN] Comando terminato con codice " << exit_code
                  << ": " << cmd << "\n";
    }
    return result;
}

// ─────────────────────────────────────────────
// Classe: NmapRunner
// ─────────────────────────────────────────────
class NmapRunner {
public:
    std::string target;
    std::string output_xml;
    std::string output_dir;

    NmapRunner(const std::string& t, const std::string& dir = "./results")
        : target(t), output_dir(dir) {
        fs::create_directories(dir);
        output_xml = dir + "/scan_" + sanitize(t) + ".xml";
    }

    // Avvia la scansione Nmap con rilevamento versioni + script vulners
    bool run() {
        std::string cmd = "nmap -sV --script=vulners -oX "
                          + output_xml + " " + target + " 2>&1";

        std::cout << "[NMAP] Avvio scansione su: " << target << "\n";
        std::cout << "[NMAP] Output XML -> " << output_xml << "\n";
        std::cout << "[NMAP] Comando: " << cmd << "\n\n";

        try {
            std::string out = exec_command(cmd);
            std::cout << out << "\n";

            if (fs::exists(output_xml)) {
                std::cout << "[NMAP] Scansione completata. File XML creato.\n";
                return true;
            } else {
                std::cerr << "[NMAP] ERRORE: file XML non trovato.\n";
                return false;
            }
        } catch (const std::exception& e) {
            std::cerr << "[NMAP] Eccezione: " << e.what() << "\n";
            return false;
        }
    }

    const std::string& get_xml_path() const { return output_xml; }

private:
    // Rimuove caratteri non sicuri per usare il target come nome file
    static std::string sanitize(const std::string& s) {
        std::string out;
        for (char c : s) {
            out += (std::isalnum(c) || c == '.') ? c : '_';
        }
        return out;
    }
};

// ─────────────────────────────────────────────
// Classe: SearchsploitRunner
// ─────────────────────────────────────────────
class SearchsploitRunner {
public:
    std::string xml_path;
    std::string output_dir;

    SearchsploitRunner(const std::string& xml, const std::string& dir = "./results")
        : xml_path(xml), output_dir(dir) {}

    // Interroga searchsploit usando il file XML di Nmap
    std::string run() {
        // --nmap: legge direttamente l'XML di Nmap
        // -j: output JSON (più facile da parsare in Python)
        std::string cmd = "searchsploit --nmap " + xml_path
                          + " -j 2>&1";

        std::cout << "[SEARCHSPLOIT] Analisi dell'XML: " << xml_path << "\n";
        std::cout << "[SEARCHSPLOIT] Comando: " << cmd << "\n\n";

        try {
            std::string result = exec_command(cmd);

            // Salva il JSON per il logic-mapper Python
            std::string json_out = output_dir + "/searchsploit_results.json";
            std::ofstream ofs(json_out);
            if (ofs.is_open()) {
                ofs << result;
                std::cout << "[SEARCHSPLOIT] Risultati salvati in: "
                           << json_out << "\n";
            }

            return result;
        } catch (const std::exception& e) {
            std::cerr << "[SEARCHSPLOIT] Eccezione: " << e.what() << "\n";
            return "";
        }
    }
};

// ─────────────────────────────────────────────
// Classe: PythonBridge
// Lancia il logic-mapper Python passando i percorsi dei file
// ─────────────────────────────────────────────
class PythonBridge {
public:
    std::string xml_path;
    std::string json_path;
    std::string script_path;

    PythonBridge(const std::string& xml,
                 const std::string& json,
                 const std::string& script = "./logic_mapper.py")
        : xml_path(xml), json_path(json), script_path(script) {}

    bool invoke() {
        std::string cmd = "python3 " + script_path
                          + " --xml "  + xml_path
                          + " --json " + json_path
                          + " 2>&1";

        std::cout << "\n[PYTHON-BRIDGE] Invocazione logic_mapper.py\n";
        std::cout << "[PYTHON-BRIDGE] Comando: " << cmd << "\n\n";

        try {
            std::string out = exec_command(cmd);
            std::cout << out << "\n";
            return true;
        } catch (const std::exception& e) {
            std::cerr << "[PYTHON-BRIDGE] Eccezione: " << e.what() << "\n";
            return false;
        }
    }
};

// ─────────────────────────────────────────────
// main
// ─────────────────────────────────────────────
int main(int argc, char* argv[]) {
    std::cout << "==============================================\n";
    std::cout << "   Security Scanner Runner (C++) - Esame Lab\n";
    std::cout << "==============================================\n\n";

    if (argc < 2) {
        std::cerr << "Uso: " << argv[0] << " <target_ip_o_range>\n";
        std::cerr << "Es:  " << argv[0] << " 192.168.1.1\n";
        std::cerr << "Es:  " << argv[0] << " 192.168.1.0/24\n";
        return 1;
    }

    std::string target    = argv[1];
    std::string result_dir = "./results";

    // ── Fase 1: Nmap ──────────────────────────
    NmapRunner nmap(target, result_dir);
    if (!nmap.run()) {
        std::cerr << "[MAIN] Scansione Nmap fallita. Interruzione.\n";
        return 2;
    }

    // ── Fase 2: Searchsploit ──────────────────
    SearchsploitRunner ss(nmap.get_xml_path(), result_dir);
    ss.run();  // anche se vuoto, Python gestirà il caso

    // ── Fase 3: Invoca il logic-mapper Python ─
    std::string json_path = result_dir + "/searchsploit_results.json";
    PythonBridge bridge(nmap.get_xml_path(), json_path);
    bridge.invoke();

    std::cout << "\n[MAIN] Pipeline completata.\n";
    return 0;
}
