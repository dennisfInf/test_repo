#include "bristol_fashion_array.h"
namespace emp
{
    ostream &operator<<(ostream &stream, const bristol_fashion_gate &gate)
    {
        return stream << gate.type << ' ' << gate.wire1 << ' ' << gate.wire2 << ' ' << gate.wire3 << ' ' << gate.mand_index;
    }

    void compute_static(BristolFashion_array *this_, rep_array_unsliced<block> out, rep_array_unsliced<block> in,
                        int num_parallel, SHRepArray *rep_exec)
    {
        this_->compute(out, in, num_parallel, rep_exec);
    }
    void BristolFashion_array::from_file_extended(string filename)
    {

        if (!file_exists(filename))
        {
            cerr << "File doesn't exist: " << filename << '\n';
            exit(1);
        }
        ifstream file(filename);

        file >> num_gate >> num_wire;
        int num_input_values, num_output_values;

        file >> num_input_values;
        for (int i = 0; i < num_input_values; i++)
        {
            int tmp;
            file >> tmp;
            num_input += tmp;
        }
        file >> num_output_values;
        for (int i = 0; i < num_output_values; i++)
        {
            int tmp;
            file >> tmp;
            num_output += tmp;
        }

        gates.resize(num_gate);

        string gate_type; // todo might be faster with char...
        int gate_input_wires, gate_output_wires;
        for (int i = 0; i < num_gate; i++) // for gate
        {
            file >> gate_input_wires >> gate_output_wires;
            if (gate_input_wires == 2)
            {
                file >> gates[i].wire1 >> gates[i].wire2 >> gates[i].wire3 >> gate_type;
                if (gate_type == "AND" || gate_type == "MAND")
                {
                    gates[i].type = AND;
                    num_and_gate++;
                }
                else if (gate_type == "XOR")
                {
                    gates[i].type = XOR_;
                }
                else
                {
                    assert("Unrecognized gate" && false);
                }
            }
            else if (gate_input_wires == 1)
            { // INV gate
                file >> gates[i].wire1 >> gates[i].wire2 >> gate_type;
                if (gate_type == "INV")
                {
                    gates[i].type = INV;
                }
                else if (gate_type == "EQW")
                {
                    gates[i].type = EQW;
                }
                else
                {
                    assert("Unrecognized gate" && false);
                }
            }
            else
            { // MAND gate
                gates[i].mand_index = mand_input_lists.size();
                gates[i].type = MAND;
                vector<int> input_list(gate_input_wires), output_list(gate_output_wires);

                for (int j = 0; j < gate_input_wires; j++)
                {
                    file >> input_list[j];
                }
                for (int j = 0; j < gate_output_wires; j++)
                {
                    file >> output_list[j];
                }
                mand_input_lists.push_back(input_list);
                mand_output_lists.push_back(output_list);
                max_gate_input_wires = max(max_gate_input_wires, gate_input_wires);
                max_gate_output_wires = max(max_gate_output_wires, gate_output_wires);
                file >> gate_type;
                assert(gate_type == "MAND");
            }
        }
    }
    void BristolFashion_array::compute_multithreaded(rep_array_unsliced<block> out, rep_array_unsliced<block> in, uint num_parallel_copies_of_circuit_not_threads)
    {
        // TODO: better logic to spin up an optimal number of threads, rather than all of them
        uint copies_per_thread = num_parallel_copies_of_circuit_not_threads / NUM_THREADS;
        vector<thread> threads;
        for (uint i = 0; i < NUM_THREADS; i++)
        {
            uint thread_section_start_copies = i * copies_per_thread;
            uint thread_section_length_copies = -1;
            if (i == NUM_THREADS - 1)
            {
                thread_section_length_copies = num_parallel_copies_of_circuit_not_threads - thread_section_start_copies;
            }
            else
            {
                thread_section_length_copies = copies_per_thread;
            }
            assert(thread_section_length_copies > 0);
            assert(num_input % 128 == 0);
            assert(num_output % 128 == 0);
            uint num_input_blocks = num_input / 128;
            uint num_output_blocks = num_output / 128;
            rep_array_unsliced<block> out_section = out.window(thread_section_start_copies * num_output_blocks,
                                                               thread_section_length_copies * num_output_blocks);
            rep_array_unsliced<block> in_section = in.window(thread_section_start_copies * num_input_blocks,
                                                             thread_section_length_copies * num_input_blocks);
            // this calls the thread constructor and stores in the back of the vector
            threads.emplace_back(compute_static, this, out_section, in_section, thread_section_length_copies, rep_execs[i]);
        }
        for (uint i = 0; i < NUM_THREADS; i++)
        {
            threads[i].join();
        }
    }
}