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

#include "lib/intel-pt.h"
#include "lib/load_elf.h"

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
    switch (packet.type)
    {
        case ppt_cbr:
            printf("CBR: %d\n", packet.payload.cbr.ratio);
            break;
        case ppt_cyc:
            printf("CBR: %d\n", packet.payload.cbr.ratio);
            break;
        case ppt_exstop:
            cout << "EXSTOP!" << endl;
            break;
        case ppt_fup:
            printf("FUP: 0x%lX\n", packet.payload.ip.ip);
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
            cout << "PTW: " << packet.payload.ptw.payload << endl;
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
            printf("TIP: 0x%lX\n", packet.payload.ip.ip);
            break;
        case ppt_tip_pgd:
            printf("TIP_PGD: 0x%lX\n", packet.payload.ip.ip);
            break;
        case ppt_tip_pge:
            printf("TIP_PGE: 0x%lX\n", packet.payload.ip.ip);
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

perf_event_mmap_page* alloc_pt_buf()
{
    // Define event attribute object
    perf_event_attr attr;

    printf("Allocating buffer for IPT...\n");
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

int handle_events(struct pt_insn_decoder *decoder, int status)
{
    while (status & pts_event_pending) {
        struct pt_event event;

        status = pt_insn_event(decoder, &event, sizeof(event));
        if (status < 0)
            break;

        // <process event>(&event);
    }

    return status;
}

int pktdecode(struct pt_packet_decoder *decoder)
{
    struct pt_packet packet;
    pt_packet_type prevtype = ppt_unknown;
    int status;

    // Try synchronizing until something gets written in the buffer
    printf("Synchronizing...\n");
    do
    {
        status = pt_pkt_sync_forward(decoder);
    } while (status == -pte_eos);

    if (status < 0)
    {
        report_error(status);
    }

    printf("Decoding...\n");

    while (true)
    {
        status = pt_pkt_next(decoder, &packet, sizeof(packet));

        if (status < 0)
        {
            break;
        }

        if (packet.type != ppt_pad
            && packet.type != ppt_fup
            && packet.type != ppt_tip
            && packet.type != ppt_tip_pgd
            && packet.type != ppt_tip_pge
            && packet.type != ppt_cbr)
        {
            print_payload(packet);
        }

        prevtype = packet.type;
    }

    report_error(status);

    return status;
}

int insndecode(struct pt_insn_decoder *decoder)
{
    struct pt_insn insn;
    int status;

    // Try synchronizing until something gets written in the buffer
    printf("Synchronizing...\n");
    do
    {
        status = pt_insn_sync_forward(decoder);
    } while (status == -pte_eos);

    if (status < 0)
    {
        report_error(status);
    }

    printf("Decoding...\n");

    while (true)
    {

        cout << "START" << endl;

        status = handle_events(decoder, status);
        if (status < 0)
        {
            break;
        }

        status = pt_insn_next(decoder, &insn, sizeof(insn));

        if (insn.iclass != ptic_error)
        {
            cout << "INSN " << insn.ip << endl;
        }
        
        if (status < 0)
        {
            break;
        }
    }

    report_error(status);

    return status;
}

int main(int argc, char** argv)
{
    // Arg 1: target PID
    TARGET_CMD = argv[1];
    char* const command[] = {TARGET_CMD, NULL};
    TARGET_PID = fork();
    
    // Start target executable in child process
    if (TARGET_PID == 0)
    {
        // TODO: Find out a way to do this from this side just after execve!
        // Pause execution of child process pending decoder setup
        // raise(SIGSTOP);
        // Execute target
        execve(TARGET_CMD, command, environ);
        // If this command runs something has gone terribly wrong
        exit(1);
    }

    printf("Target: %i\n", TARGET_PID);

    // Allocate memory buffer for IPT
    perf_event_mmap_page* header = alloc_pt_buf();


    // ==BEGIN DECODER INIT==
    struct pt_packet_decoder* pktdecoder;
    struct pt_insn_decoder* insndecoder;
    struct pt_config config;
    int status;

    printf("Allocating decoder...\n");

    memset(&config, 0, sizeof(config));
    pt_config_init(&config);
    // TODO: Make sure this is correct
    config.begin = (uint8_t *)header->aux_head;
    config.end = config.begin+header->aux_size;

    pktdecoder = pt_pkt_alloc_decoder(&config);
    insndecoder = pt_insn_alloc_decoder(&config);
    
    if (!pktdecoder)
    {
        printf("Failed to allocate packet decoder!\n");
        end_child_process();
        exit(EXIT_FAILURE);
    }

    if (!insndecoder)
    {
        printf("Failed to allocate instruction decoder!\n");
        end_child_process();
        exit(EXIT_FAILURE);
    }

    // Load image from the target executable
    char targetfile[64];
    sprintf(targetfile, "/proc/%u/exe", TARGET_PID);
    status = load_elf(NULL, pt_insn_get_image(insndecoder), targetfile, 0ull, "target", true);
    
    if (status < 0)
    {
        report_error(status);
    }
    

    // ==BEGIN DECODING==

    // Continue execution of target process
    kill(TARGET_PID, SIGCONT);

    pktdecode(pktdecoder);
    // insndecode(insndecoder);

    pt_pkt_free_decoder(pktdecoder);
    pt_insn_free_decoder(insndecoder);
    
    // Just in case
    end_child_process();

    return 0;
}