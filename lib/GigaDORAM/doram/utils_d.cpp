#include "utils_d.h"

namespace emp
{
    unsigned long long sample_unif_from_prg(PRG *prg, unsigned long long from, unsigned long long to)
    {
        unsigned long long tmp;
        do
        {
            prg->random_data(&tmp, sizeof(unsigned long long)); //! could this be nonuniform and mod or something?
        } while (tmp >= ULONG_LONG_MAX -
                            (ULONG_LONG_MAX % (to - from))); //! off by 1 err? -- now I think not, because we start at 0

        return (tmp % (to - from)) + from;
    }

    template <typename T>
    block local_shuffle(PRG *prg, T *list, u_int list_len)
    {
        T temp = 0;
        u_int rnd = 0;
        block perm_seed;

        prg->random_block(&perm_seed);
        PRG temp_prg = PRG(perm_seed, 0);

        for (int i = list_len - 1; i > 0; i--)
        {
            rnd = sample_unif_from_prg(&temp_prg, 0, i);
            temp = list[rnd]; //* potential optimization -- call function only once
            list[rnd] = list[i];
            list[i] = temp;
        }

        return perm_seed;
    }

    int next_party(int wrt)
    {
        // assert(party != 0); //?remove these asserts for efficiency?
        return (wrt % 3) + 1;
    }

    int prev_party(int wrt)
    {
        // assert(party != 0);
        return ((wrt + 1) % 3) + 1;
    }

    void init_timing_file()
    {
        timing_file.open("doram_timing_report" + std::__cxx11::to_string(party) + ".txt", std::ios::out);
        if (!timing_file)
        {
            std::cerr << "failed to open DORAM timing report, exiting..." << endl;
            exit(1);
        }
    }

    void parse_host_and_port(string host_and_port, string &host, uint &port)
    {
        auto colon_pos = host_and_port.find(':');
        if (colon_pos != string::npos)
        {
            host = host_and_port.substr(0, colon_pos);
            port = stoi(host_and_port.substr(colon_pos + 1));
        }
        else
        {
            host = "127.0.0.1";
            port = stoi(host_and_port);
        }
    }
    /* void send_data(string data)
    {
        int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0)
        {
            std::cout << "fehler beim Erstellen des Sockets" << std::endl;
            perror("Fehler beim Erstellen des Sockets");
            return;
        }
        // Schritt 2: Zieladresse definieren
        struct sockaddr_in destAddr;
        std::memset(&destAddr, 0, sizeof(destAddr));
        destAddr.sin_family = AF_INET;
        destAddr.sin_port = htons(emp::webserver_port);

        if (inet_pton(AF_INET, emp::webserver_address.c_str(), &destAddr.sin_addr) <= 0)
        {
            std::cout << "Ungültige Ziel-IP-Adresse" << std::endl;
            perror("Ungültige Ziel-IP-Adresse");
            close(sockfd);
            return;
        }

        const char *message = data.c_str();

        ssize_t bytesSent = sendto(
            sockfd,                       // Socket-Deskriptor
            message,                      // Nachricht, die gesendet werden soll
            std::strlen(message),         // Länge der Nachricht
            0,                            // Flags (0 = keine speziellen Flags)
            (struct sockaddr *)&destAddr, // Zieladresse
            sizeof(destAddr)              // Größe der Zieladressstruktur
        );

        if (bytesSent < 0)
        {
            std::cout << "Fehler beim Senden des Datagramms" << std::endl;
            perror("Fehler beim Senden des Datagramms");
            close(sockfd);
            return;
        }

        // std::cout << "Nachricht gesendet: " << message << std::endl;
        close(sockfd);
    } */
}