#include <iostream>
#include <fstream>
#include <string>
#include <sstream>

#include <fcntl.h>
#include <unistd.h>
#include <syscall.h>
#include <sys/mman.h>
#include <linux/perf_event.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <intel-pt.h>
#include <asm/ioctl.h>
#include <sys/ptrace.h>

#include "lib/load_elf.h"
extern "C" {
#include "ptxed_util.c"
#include "lib/xed-interface.h"
}

using namespace std;

char* TARGET_CMD;
pid_t TARGET_PID;
int FD_IPT, FD_CNT;

const int DATA_SIZE = 4096;
const int AUX_SIZE = 4096;

void report_error(int err)
{
    printf("ERROR %d: %s\n", err, pt_errstr(pt_errcode(err)));
}

void cleanup()
{
    printf("Cleaning up...\n");
    int status;
    // Disable the PERF event counters
    syscall(SYS_ioctl, FD_IPT, PERF_EVENT_IOC_DISABLE, 0);
    syscall(SYS_ioctl, FD_CNT, PERF_EVENT_IOC_DISABLE, 0);
    // Close the perf file descriptors
    close(FD_IPT);
    close(FD_CNT);
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

void sig_handler(int sig)
{
    // TODO: Handle other signals differently?
    cleanup();
    exit(EXIT_FAILURE);
}

static int load_image(
         ptxed_decoder *decoder,
         pt_image *image,
         char* prog)
{
	int status;
	char filename[16];

    // Parse the maps file of target process
	sprintf(filename, "/proc/%d/maps", TARGET_PID);

	ifstream mapsfile(filename);
    string line;

    while (getline(mapsfile, line))
    {
        stringstream ss;
        unsigned long long base = 0ull;
        int lsplit, rlen;

        unsigned long startaddr, endaddr;
        string acc, target;

        // Get base address of section
        lsplit = 0;
        rlen = line.find('-', lsplit+1)-lsplit;
        ss.clear();
        ss << hex << line.substr(lsplit, rlen);
        ss >> startaddr;

        // Get end address of section
        lsplit = lsplit+rlen+1;
        rlen = line.find(' ', lsplit+1)-lsplit;
        ss.clear();
        ss << hex << line.substr(lsplit, rlen);
        ss >> endaddr;

        // Get access modifiers
        lsplit = lsplit+rlen+1;
        rlen = line.find(' ', lsplit+1)-lsplit;
        acc = line.substr(lsplit, rlen);

        // Skip non-executable sections
        if (acc.find('x') != -1)
        {
            // Get section identifier
            lsplit = line.find_last_of(' ')+1;
            target = line.substr(lsplit);

            // Skip non-filename identifiers
            // target.compare(TARGET_CMD) == 0)//
            if (target.length() > 0 && target[0] != '[')
            {
                printf("%s: base=0x%lx\n", target.c_str(), startaddr);

                // Load the appropriate file
                status = load_elf(decoder->iscache, image, target.c_str(),
                         startaddr, prog, true);
            }
        }
    }

    mapsfile.close();

	if (status < 0)
	{
        report_error(status);
        printf("ERROR!\n");
	}

	return status;
}

perf_event_mmap_page* alloc_pt_buf()
{
    // Define event attribute object
    perf_event_attr attr_ipt, attr_cnt;

    printf("Allocating buffer for IPT...\n");
    memset(&attr_ipt, 0, sizeof(attr_ipt));
    attr_ipt.size = sizeof(attr_ipt);
    attr_ipt.exclude_kernel = 1;
    attr_ipt.exclude_idle = 1;
    attr_ipt.context_switch = 1;
    
    // attr_ipt.use_clockid = 1;
    // attr_ipt.exclude_hv = 1;
    attr_ipt.disabled = 1;
    // attr_ipt.enable_on_exec = 1;

    // Read IPT PMU type from system file
    ifstream typeFile;
    typeFile.open("/sys/bus/event_source/devices/intel_pt/type");
    typeFile >> attr_ipt.type;
    typeFile.close();

    memset(&attr_cnt, 0, sizeof(attr_cnt));
    attr_cnt.size = sizeof(attr_cnt);
    attr_cnt.exclude_kernel = 1;
    attr_cnt.context_switch = 1;
    attr_cnt.exclude_idle = 1;
    attr_cnt.type = PERF_TYPE_HARDWARE;
    // attr_cnt.exclude_hv = 1;
    // attr_cnt.disabled = 1;

    // Open perf event counter
    FD_IPT = syscall(SYS_perf_event_open, &attr_ipt, TARGET_PID, -1, -1, 0);
    FD_CNT = syscall(SYS_perf_event_open, &attr_cnt, TARGET_PID, -1, -1, 0);

    void* base = mmap(NULL, (1+DATA_SIZE) * PAGE_SIZE, PROT_WRITE, MAP_SHARED, FD_IPT, 0);
    if (base == MAP_FAILED)
    {
        printf("Failed to allocate BASE\n");
        exit(EXIT_FAILURE);
    }

    printf("\tBASE:\t%p\n", base);

    perf_event_mmap_page* header = (perf_event_mmap_page *)base;
    header->data_size = DATA_SIZE * PAGE_SIZE;
    header->data_head = (uint64_t)header + header->data_offset;
    header->data_tail = header->data_head + header->data_size;

    printf("\tDATA:\t%p-%p\n",
            (uint8_t *)header->data_head,
            (uint8_t *)header->data_tail);

    header->aux_offset  = header->data_offset + header->data_size;
    header->aux_size    = AUX_SIZE * PAGE_SIZE;

    void* aux = mmap(NULL, header->aux_size, PROT_READ, MAP_SHARED, FD_IPT, header->aux_offset);
    if (aux == MAP_FAILED)
    {
        printf("Failed to allocate AUX\n");
        cleanup();
        exit(EXIT_FAILURE);
    }

    header->aux_head = (uint64_t)aux;
    header->aux_tail = (uint64_t)header->aux_head + header->aux_size;

    printf("\tAUX:\t%p-%p\n",
            (uint8_t *)header->aux_head,
            (uint8_t *)header->aux_tail);

    return header;
}

int main(int argc, char** argv)
{
    // Assign signal handlers
    signal(SIGINT, sig_handler);

    // Arg 1: target PID
    TARGET_CMD = argv[1];
    char* const command[] = {TARGET_CMD, NULL};
    TARGET_PID = fork();

    // Start target executable in child process
    if (TARGET_PID == 0)
    {
        // Pause execution of child process on exec pending decoder setup
        syscall(SYS_ptrace, PTRACE_TRACEME);
        // Execute target
        execv(TARGET_CMD, command);
        // If this command runs something has gone terribly wrong
        exit(1);
    }
    

    printf("Target PID: %i\n", TARGET_PID);

    // Allocate memory buffer for IPT
    perf_event_mmap_page* header;
    int	childstatus;
    waitpid(TARGET_PID, &childstatus, 0);

    if (WIFSTOPPED(childstatus) && WSTOPSIG(childstatus) == SIGTRAP)
    {
        header = alloc_pt_buf();
        syscall(SYS_ptrace, PTRACE_CONT, TARGET_PID);
        syscall(SYS_ioctl, FD_IPT, PERF_EVENT_IOC_ENABLE);
    }

	struct ptxed_decoder decoder;
	struct ptxed_options options;
	struct ptxed_stats stats;
	struct pt_config config;
	struct pt_image *image;
	int errcode, i;

    image = NULL;

    memset(&options, 0, sizeof(options));
	memset(&stats, 0, sizeof(stats));

	pt_config_init(&config);
    config.begin = (uint8_t *)header->aux_head;
    config.end = (uint8_t *)header->aux_tail;
    
	errcode = ptxed_init_decoder(&decoder);
	if (errcode < 0)
    {
		report_error(errcode);
        cleanup();
        exit(1);
	}

    pt_sb_notify_error(decoder.session, ptxed_print_error, &options);

	image = pt_image_alloc(NULL);
	if (!image)
    {
		fprintf(stderr, "%s: failed to allocate image.\n", TARGET_CMD);
        cleanup();
        exit(1);
	}

    // TODO
    errcode = load_image(&decoder, image, TARGET_CMD);
    if (errcode < 0)
    {
        report_error(errcode);
        cleanup();
        exit(1);
    }

    // options.print_offset = 1;
    // options.print_time = 1;
    // options.print_event_time = 1;
    // options.print_event_ip = 1;
    // options.check = 1;
    // options.dont_print_insn = 1;
    options.print_stats = 1;
    options.print_raw_insn = 1;
    options.track_image = 1;

    decoder.block.flags.variant.block.enable_tick_events = 1;
    decoder.insn.flags.variant.insn.enable_tick_events = 1;

    // TODO
    // decoder.pevent.vdso_x64 = "--event:tick";
    // decoder.pevent.begin = header->data_head;
    // decoder.pevent.end = header->data_tail;
    // decoder.type = pdt_insn_decoder;

    alloc_decoder(&decoder, &config, image, &options, TARGET_CMD);
	if (!ptxed_have_decoder(&decoder))
    {
		fprintf(stderr, "%s: no pt.\n", TARGET_CMD);
        cleanup();
		exit(1);
	}

    xed_tables_init();

	if (options.print_stats && !stats.flags) {
		stats.flags |= ptxed_stat_insn;

		if (decoder.type == pdt_block_decoder)
			stats.flags |= ptxed_stat_blocks;
	}

	errcode = pt_sb_init_decoders(decoder.session);
	if (errcode < 0)
    {
		report_error(errcode);
        cleanup();
        exit(1);
	}

    // Start decoding
	decode(&decoder, &options, options.print_stats ? &stats : NULL);

    // Test for comparison
    long unsigned cnt;
    syscall(SYS_ioctl, FD_CNT, PERF_EVENT_IOC_DISABLE, 0);
    read(FD_CNT, &cnt, sizeof(cnt));
    printf("Actual insn: %lu\n", cnt);

	if (options.print_stats)
		print_stats(&stats);

    cleanup();

    return 0;
}