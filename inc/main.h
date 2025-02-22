

struct Benchmarks
{
    double ureg_time;
    double create_entry;
    double proof_entry;
    double proof_creation;
    bookkeeping::BenchmarkInsertEntry benchmarks_ie;
};

void writeBenchmarksToFile(Benchmarks &data, const std::string &filename, const int &runs)
{
    data.benchmarks_ie.mpc1_time /= runs;
    data.benchmarks_ie.mpc2_time /= runs;
    data.benchmarks_ie.total_time /= runs;
    data.create_entry /= runs;
    data.proof_creation /= runs;
    data.proof_entry /= runs;
    data.ureg_time /= runs;

    std::cout << std::fixed << std::setprecision(2); // Set precision for double formatting
    std::cout << "Average time for U_Reg: " << data.ureg_time << "\n";
    std::cout << "Average time for Create Entry: " << data.create_entry << "\n";
    std::cout << "Proof entry time: " << data.proof_entry << "\n";
    std::cout << "Average time for Insert Entry: " << data.benchmarks_ie.total_time << "\n";
    std::cout << "From that time spent in MPC1: " << data.benchmarks_ie.mpc1_time << "\n";
    std::cout << "From that time spent in MPC2: " << data.benchmarks_ie.mpc2_time << "\n"
              << std::endl;

    std::ofstream file(filename); // Open the file for writing

    if (!file.is_open())
    {
        std::cout << "Failed to open file: " << filename << std::endl;
        return;
    }

    // Write each double with a description
    file << std::fixed << std::setprecision(2); // Set precision for double formatting
    file << "Average time for U_Reg: " << data.ureg_time << "\n";
    file << "Average time for Create Entry: " << data.create_entry << "\n";
    file << "Proof entry time: " << data.proof_entry << "\n";
    file << "Average time for Insert Entry: " << data.benchmarks_ie.total_time << "\n";
    file << "From that time spent in MPC1: " << data.benchmarks_ie.mpc1_time << "\n";
    file << "From that time spent in MPC2: " << data.benchmarks_ie.mpc2_time << "\n";
    file.close(); // Close the file
}

template <typename T>
int start_protocol(T *ho, Config::Values &config, std::tuple<std::vector<Networking::Client>, uint8_t> &clients, GS::CRS &crs_nizk, int &runs,
                   int &batch_size)
{

    BilinearGroup::BN period = BN(0);
    BilinearGroup::BN message = BN(1337);
    // Builds a precomputation table for the crs of the NIZK
    Benchmarks benchmarks;
    // Only the bootstrapping node acts as a home operator for the user. The other nodes only participate in the DKG's, threshold-algorithms and MPC's.
    if (config.bootstrap)
    {
        tsps::PublicParameters pp = ho->get_public_parameters();
        bookkeeping::PublicKeys public_keys = ho->get_public_keys();
        // This runs the registration process and creaty entry 50 times in sequence to get an average time
        for (int i = 0; i < runs * batch_size; i++)
        {
            std::cout << "run: " << i << std::endl;
            auto start = std::chrono::high_resolution_clock::now();
            // Creates a user object, which already generates the BLS keys for the user and initializes the required crs's, public parameters and public keys.
            bookkeeping::User user(public_keys.ek_all, public_keys.vk_all, public_keys.vk_ho, pp, crs_nizk);
            auto start_proof = std::chrono::high_resolution_clock::now();
            // Creates a nizk proof for the BLS secret key of the user
            bookkeeping::proof_sk_u proof_sk_u = user.create_proof_for_sk_u();
            auto end_proof = std::chrono::high_resolution_clock::now();

            std::chrono::duration<double> elapsed_proof = end_proof - start_proof;
            benchmarks.proof_creation += elapsed_proof.count();
            // Registers the user at the home operator by sending the proof to the home operator.
            // The home operator verifies the proof and if it is valid, the user is registered and a threshold signature is
            // returned signing the public key and the ORAM address.
            std::cout << "register user " << std::endl;
            bookkeeping::ThresholdSignature threshold_sig = ho->register_user(proof_sk_u);
            // Finalizes the registration by sending the threshold signature and the address to the user, which verifies it.
            user.finalize_registration(threshold_sig.address, threshold_sig.threshold_signature);

            auto end = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double> elapsed = end - start;
            benchmarks.ureg_time += elapsed.count();
            auto start_create_entry = std::chrono::high_resolution_clock::now();
            auto start_ce = std::chrono::high_resolution_clock::now();
            // Creates a proof for creating an entry in the bookkeeping system
            bookkeeping::proof_create_entry create_entry_proof = user.create_proof_for_create_entry(period, message);
            // creates an object for the home operator with only the proof and the ciphertext
            bookkeeping::proof_create_entry_user create_entry_proof_user = {create_entry_proof.ciphertext_r.c,
                                                                            create_entry_proof.proof};
            auto end_ce = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double> elapsed_ce = end_ce - start_ce;
            std::cout << "create entry proof time: " << elapsed_ce.count() << " seconds" << std::endl;

            auto start_verify_proof = std::chrono::high_resolution_clock::now();
            // Sends the proofs to the home operator, which verifies them and if they are valid, the home operator signs the message, the ciphertext and the message.
            // Also the entry is added to the pending list of the home operator.
            BLS::Signature bls_sig_ho = ho->create_entry(create_entry_proof_user, message, period);
            auto end_verify_proof = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double> elapsed_verify_proof = end_verify_proof - start_verify_proof;
            std::cout << "verify proof time: " << elapsed_verify_proof.count() << " seconds" << std::endl;
            // checks if the home opertaors signature is valid and pushes the entry to the users list of entries
            bookkeeping::Entry entry = user.finalize_create_entry(message, create_entry_proof.ciphertext_r, bls_sig_ho.sig, create_entry_proof.hash);
            auto end_create_entry = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double> elapsed_create_entry = end_create_entry - start_create_entry;
            benchmarks.create_entry += elapsed_create_entry.count();
            auto start_prove_entry = std::chrono::high_resolution_clock::now();

            bookkeeping::proof_prove_entry proof_entry = user.create_proof_for_prove_entry(entry);
            std::vector<uint8_t> buffer;
            BilinearGroup::Serializer serializer(buffer);
            serializer << BilinearGroup::BN(1);
            serializer << proof_entry.proof;
            std::cout << "buffer proof size: " << buffer.size() << std::endl;
            if (ho->prove_entry(proof_entry))
            {
                std::cout << "proof entry successful" << std::endl;
            }
            else
            {
                std::cout << "proof entry failed" << std::endl;
            }
            auto end_prove_entry = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double> elapsed_proof_entry = end_prove_entry - start_prove_entry;
            benchmarks.proof_entry += elapsed_proof_entry.count();
        }
        // Since 50 pending entries are already enqueued, the home operator runs 50 times insert entry
        std::ostringstream oss;

        oss << "/app/benchmarks/party_" << static_cast<int>(std::get<1>(clients)) << "_n_" << static_cast<int>(config.n_parties) << "_t_" << static_cast<int>(config.t) << "_addr_" << static_cast<int>(config.oram_addresses);

        writeBenchmarksToFile(benchmarks, oss.str(), runs);
        benchmarks.benchmarks_ie = ho->insert_entry(runs, batch_size);
    }
    else
    {
        // Because the other nodes don't have any pending entries, they don't fetch any pending entries and calculate everything required to insert the entries
        // of the bootstrapper.
        benchmarks.benchmarks_ie = ho->calc_decryption_shares(period, message, runs, batch_size);
    }
    std::ostringstream oss;
    oss << "/app/benchmarks/party_" << static_cast<int>(std::get<1>(clients)) << "_n_" << static_cast<int>(config.n_parties) << "_t_" << static_cast<int>(config.t) << "_addr_" << static_cast<int>(config.oram_addresses);
    writeBenchmarksToFile(benchmarks, oss.str(), runs);
    std::cout << config.bootstrap << "party" << std::endl;
    sleep(1000000000);
    return 0;
}