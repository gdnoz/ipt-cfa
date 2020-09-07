#include <iostream>
#include <sstream>
#include <fstream>
#include <bitset>

#include <elf.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <syscall.h>
#include <sys/mman.h>
#include <linux/perf_event.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include "/opt/libipt/libipt/include/intel-pt.h"

using namespace std;

char* TARGET_CMD;
pid_t TARGET_PID;

const int DATA_SIZE = 1024;
const int AUX_SIZE = 1024;

void report_error(int err)
{
    printf("ERROR %d: %s\n", err, pt_errstr(pt_errcode(err)));
}

void print_payload(pt_packet packet)
{
    char hex_str[18];

    switch (packet.type)
    {
        case ppt_cbr:
            cout << "CBR: " << packet.payload.cbr.ratio << endl;
            break;
        case ppt_cyc:
            cout << "CYC: " << packet.payload.cyc.value << endl;
            break;
        case ppt_exstop:
            cout << "EXSTOP!" << endl;
            break;
        case ppt_fup:
            sprintf(hex_str, "0x%lX", packet.payload.ip.ip);
            cout << "FUP: " << hex_str << endl;
            break;
        case ppt_invalid:
            cout << "INVALID!" << endl;
            break;
        case ppt_mnt:
            cout << "MNT: " << endl; // TODO?
            break;
        case ppt_mode:
            cout << "MODE" << endl; // TODO?
            break;
        case ppt_mtc:
            cout << "MTC" << endl; // TODO?
            break;
        case ppt_mwait:
            cout << "MWAIT" << endl;
            break;
        case ppt_ovf:
            cout << "OVERFLOW!" << endl;
            break;
        case ppt_pad:
            cout << "PAD" << endl;
            break;
        case ppt_pip:
            cout << "PIP: " << packet.payload.pip.cr3 << endl;
            break;
        case ppt_psb:
            cout << "PSB" << endl;
            break;
        case ppt_psbend:
            cout << "PSBEND" << endl;
            break;
        case ppt_ptw:
            cout << "PTW" << packet.payload.ptw.payload << endl;
            break;
        case ppt_pwre:
            cout << "PWRE" << endl;
            break;
        case ppt_pwrx:
            cout << "PWRX" << endl;
            break;
        case ppt_stop:
            cout << "STOP" << endl;
            break;
        case ppt_tip:
            sprintf(hex_str, "0x%lX", packet.payload.ip.ip);
            cout << "TIP: " << hex_str << endl;
            break;
        case ppt_tip_pgd:
            sprintf(hex_str, "0x%lX", packet.payload.ip.ip);
            cout << "TIP_PGD: " << hex_str << endl;
            break;
        case ppt_tip_pge:
            sprintf(hex_str, "0x%lX", packet.payload.ip.ip);
            cout << "TIP_PGE: " << hex_str << endl;
            break;
        case ppt_tma:
            cout << "TMA" << endl;
            break;
        case ppt_tnt_64:
            cout << "TNT_64: " << bitset<64>(packet.payload.tnt.payload) << endl;
            break;
        case ppt_tnt_8:
            cout << "TNT_8: " << bitset<8>(packet.payload.tnt.payload) << endl;
            break;
        case ppt_tsc:
            cout << "TSC: " << packet.payload.tsc.tsc << endl;
            break;
        case ppt_unknown:
            cout << "UNKNOWN" << endl;
            break;
        case ppt_vmcs:
            cout << "VMCS: " << packet.payload.vmcs.base << endl;
            break;
        default:
            cout << "NO PACKET TYPE" << endl;
    }
}

void end_child_process()
{
    int status;
    // Send TERMINATE signal
    kill(TARGET_PID, SIGTERM);
    // Give the child process a chance to terminate gracefully
    sleep(1);
    // Check whether the process has aborted
    waitpid(TARGET_PID, &status, WUNTRACED);
    // Kill the process if it has not terminated gracefully
    if ((!WIFEXITED(status) && !WIFSIGNALED(status)) || WIFSTOPPED(status))
    {
        kill(TARGET_PID, SIGKILL);
        // Harvest the zombie child
        waitpid(TARGET_PID, &status, 0);
    }
}

void read_elf_file(char* filename, uint64_t* offset, uint64_t* size)
{
    char shname[64];
    char sname[64];

    FILE* file = fopen(filename, "rb");
    Elf64_Ehdr header;
    Elf64_Shdr sheader;
    Elf64_Shdr strheader;

    if(file)
    {
        // Read the header
        fread(&header, 1, sizeof(header), file);

        // Read the string table header
        fseek(file, header.e_shoff + header.e_shstrndx * header.e_shentsize, SEEK_SET);
        fread(&strheader, 1, sizeof(strheader), file);

        for (int i = 0; i < header.e_shnum; i++)
        {
            fseek(file, header.e_shoff + i * header.e_shentsize, SEEK_SET);
            fread(&sheader, 1, header.e_shentsize, file);

            fseek(file, strheader.sh_offset + sheader.sh_name, SEEK_SET);
            fread(sname, 1, 64, file);
            
            if (strcmp(sname, ".text") == 0)
            {
                *offset = sheader.sh_offset;
                *size = sheader.sh_size;
                break; // Assuming only one section
            }
        }

        fclose(file);
    }
}

void read_maps_file(char* filename, uint64_t* vaddr)
{
    string line;
    ifstream file;

    file.open(filename);

    while (getline(file, line))
    {
        // Get access control flags
        string acc = line.substr(line.find(" ")+1, 4);

        if (acc.find("x") != -1)
        {
            int lspace = line.find_last_of(" ");
            string label = line.substr(lspace+1, line.length()-lspace-1);

            if (label.compare(TARGET_CMD) == 0)
            {
                string start = line.substr(0, line.find("-"));
                stringstream sstart;
                sstart << hex << start;
                sstart >> *vaddr;
                break; // Assuming only one section
            }
        }
    }

    file.close();
}

void add_image_file(pt_image* image)
{
    char exefilename[64], mapsfilename[64];
    sprintf(exefilename, "/proc/%i/exe", TARGET_PID);
    sprintf(mapsfilename, "/proc/%i/maps", TARGET_PID);

    uint64_t offset, size, vaddr;

    // Get offset (of .text in ELF?)
    // Get size (of .text in ELF?)
    read_elf_file(exefilename, &offset, &size);

    // Get vaddr (of what?)
    read_maps_file(mapsfilename, &vaddr);

    pt_image_add_file(image, exefilename, offset, size, NULL, vaddr);
}

perf_event_mmap_page* alloc_pt_buf()
{
    // Define event attribute object
    perf_event_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    attr.exclude_kernel = 1;

    // Read IPT PMU type from system file
    ifstream typeFile;
    typeFile.open("/sys/bus/event_source/devices/intel_pt/type");
    typeFile >> attr.type;
    typeFile.close();

    // Open perf event counter
    int fd = syscall(SYS_perf_event_open, &attr, TARGET_PID, -1, -1, 0);

    void* base = mmap(NULL, (1+DATA_SIZE) * PAGE_SIZE, PROT_WRITE, MAP_SHARED, fd, 0);
    printf("\tBASE:\t%p\n", base);

    if (base == MAP_FAILED)
    {
        printf("Failed to allocate BASE\n");
        exit(EXIT_FAILURE);
    }

    perf_event_mmap_page* header = (perf_event_mmap_page *)base;
    header->data_head = (uint64_t)header + header->data_offset;
    header->data_tail = header->data_head + header->data_size;

    printf("\tDATA:\t%p\n", (uint8_t *)header->data_head);

    header->aux_offset  = header->data_offset + header->data_size;
    header->aux_size    = AUX_SIZE * PAGE_SIZE;

    void* aux = mmap(NULL, header->aux_size, PROT_READ, MAP_SHARED, fd,
                     header->aux_offset);

    header->aux_head = (uint64_t)aux;
    header->aux_tail = (uint64_t)header->aux_head + header->aux_size;
    
    printf("\tAUX:\t%p\n", aux);

    if (aux == MAP_FAILED)
    {
        printf("Failed to allocate AUX\n");
        end_child_process();
        exit(EXIT_FAILURE);
    }

    return header;
}

int main(int argc, char** argv)
{
    // Arg 1: target PID
    TARGET_CMD = argv[1];
    char* const command[] = {TARGET_CMD, NULL};
    TARGET_PID = fork();
    
    // Start target executable in new process
    if (TARGET_PID == 0)
    {
        // TODO: Find out a way to do this from this side just after execve!
        // Pause execution of child process pending decoder setup
        //raise(SIGSTOP);
        execve(TARGET_CMD, command, environ);
        exit(0);
    }

    printf("Target: %i\n", TARGET_PID);

    // Allocate memory buffer for IPT
    perf_event_mmap_page* header = alloc_pt_buf();

    printf("Successfully allocated memory for IPT!\n");





    // BEGIN DECODER INIT

    struct pt_packet_decoder* pktdecoder;
    // struct pt_insn_decoder* insndecoder;
    struct pt_config config;
    int status;

    memset(&config, 0, sizeof(config));
    pt_config_init(&config);
    // TODO: Find out if this is correct
    config.begin = (uint8_t *)header->aux_head;
    config.end = config.begin+header->aux_size;

    pktdecoder = pt_pkt_alloc_decoder(&config);
    // insndecoder = pt_insn_alloc_decoder(&config);
    
    if (!pktdecoder)
    // if (!insndecoder)
    {
        printf("Failed to allocate decoder!\n");
        end_child_process();
        exit(EXIT_FAILURE);
    }

    // add_image_file(pt_insn_get_image(insndecoder));

    printf("Successfully allocated decoder!\n");
    




    // BEGIN DECODER SYNCHRONIZATION

    // Continue execution of target process
    kill(TARGET_PID, SIGCONT);

    // Try synchronizing until something gets written in the buffer
    printf("Synchronizing...\n");
    do
    {
        status = pt_pkt_sync_forward(pktdecoder);
        // status = pt_insn_sync_forward(insndecoder);
    } while (status == -pte_eos);

    if (status < 0)
    {
        report_error(status);
    }





    // BEGIN DECODING

    printf("Successfully synchronized decoder!\n");
    printf("Decoding...\n");
    while (true)
    {
        struct pt_packet packet;
        // struct pt_insn insn;

        status = pt_pkt_next(pktdecoder, &packet, sizeof(packet));
        // status = pt_insn_next(insndecoder, &insn, sizeof(insn));

        if (status < 0)
        {
            report_error(status);
            break;
        }

        if (packet.type != ppt_pad)
            print_payload(packet);
        // cout << insn.raw << endl;
    }

    pt_pkt_free_decoder(pktdecoder);
    // pt_insn_free_decoder(insndecoder);

    return 0;
}