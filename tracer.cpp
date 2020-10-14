#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <vector>

#include <fcntl.h>
#include <unistd.h>
#include <syscall.h>
#include <dirent.h>
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

int FD;
char* TARGET_CMD;
pid_t TARGET_PID;

const int DATA_SIZE = 4096;
const int AUX_SIZE = 4096;

struct gm_file_link
{
    string filename;
    uint64_t base;
};

void report_error(int err)
{
    printf("ERROR %d: %s\n", err, pt_errstr(pt_errcode(err)));
}

/**
 * This function parses the maps file for the target process
 * and returns the number of mapped executable file sections.
 * If save is set to a non-zero value, it also stores each
 * section's file name and base address in a vector.
*/
static int get_linked_files(vector<gm_file_link> *links, bool save)
{
	int status, cnt = 0;
    string line;
	char *filename = new char[32];
    // Parse the maps file of target process
	sprintf(filename, "/proc/%d/maps", TARGET_PID);

    // Open file stream on maps filename
	ifstream mapsfile(filename);

    while (getline(mapsfile, line))
    {
        int lsplit, rlen;
        unsigned long startaddr;//, endaddr;
        string acc, target;
        stringstream ss;

        // Get base address of section
        lsplit = 0;
        rlen = line.find('-', lsplit+1)-lsplit;
        ss.clear();
        ss << hex << line.substr(lsplit, rlen);
        ss >> startaddr;

        // Get end address of section
        lsplit = lsplit+rlen+1;
        rlen = line.find(' ', lsplit+1)-lsplit;
        // ss.clear();
        // ss << hex << line.substr(lsplit, rlen);
        // ss >> endaddr;

        // Get access control flags
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
            if (target.length() > 0 && target[0] != '[')
            {
                // Compute library load offset
                uint64_t offset;
                elf_load_offset(target.c_str(), startaddr, &offset, TARGET_CMD);

                // Add the file information to links
                gm_file_link link;
                link.filename = target;
                link.base = offset;
                cnt++;

                if (save)
                {
                    links->push_back(link);
                }
            }
        }
    }

    mapsfile.close();

    return cnt;
}

char *trim_str(char *str)
{
    char *end;

    // Trim leading space
    while(isspace((unsigned char)*str)) str++;

    if(*str == 0)  // All spaces?
    return str;

    // Trim trailing space
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;

    // Write new null terminator character
    end[1] = '\0';

    return str;
}

int libcount()
{
    string data;
    FILE * stream;
    const int max_buffer = 256;
    char buffer[max_buffer];
    char cmd[max_buffer];
    int cnt = 0;

    sprintf(cmd, "ldd %s 2>&1",TARGET_CMD);

    stream = popen(cmd, "r");
    if (stream) {
        while (!feof(stream))
        {
            if (fgets(buffer, max_buffer, stream) != NULL)
            {
                char *line = trim_str(buffer);
                
                if (strlen(line) <= 0)
                {
                    continue;
                }

                if (line[0] == '/')
                {
                    cnt++;
                }
                else
                {
                    strtok(line, " => ");
                    strtok(NULL, " ");
                    char *token = strtok(NULL, " ");

                    if (token != NULL && token[0] == '/')
                    {
                        cnt++;
                    }
                }
            }
        }
        pclose(stream);
    }

    // Add one for the base executable
    return cnt+1;
}

void monitor_maps(void *arg)
{
    vector<struct gm_file_link> *links = (vector<struct gm_file_link> *)arg;
    // Determine the expected number of linked libraries
    int mapcnt, libcnt = libcount();

    // While the actual number of linked libraries is
    // less than the expected number, keep checking
    do
    {
        // Step child process one block ahead
        ptrace(PTRACE_SINGLEBLOCK, TARGET_PID);
        // Check current number of mapped libraries
        mapcnt = get_linked_files(links, false);
    } while (mapcnt < libcnt);

    // Load the linked libraries
    get_linked_files(links, true);
}

static int load_image(
         vector<gm_file_link> *links,
         ptxed_decoder *decoder,
         pt_image *image,
         char* prog)
{
    int status;

    printf("Loading linked libraries into decoder image...\n");

    for (int i = 0; i < links->size(); i++)
    {
        gm_file_link *cur = &((*links)[i]);

        // Load the appropriate file
        int len = cur->filename.size()+1;
        char *cfilename = new char[len];
        strcpy(cfilename, cur->filename.c_str());
        printf("+   %s: base=0x%lx\n", cur->filename.c_str(), cur->base);

        status = load_raw(decoder->iscache, image, cfilename, cur->base, prog);
    }

	return status;
}

perf_event_mmap_page* alloc_pt_buf()
{
    struct perf_event_attr attr;

    printf("Allocating buffer for IPT...\n");
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    attr.exclude_kernel = 1;
    attr.context_switch = 1;
    attr.disabled = 1;
    
    // Read IPT PMU type from system file
    ifstream typeFile;
    typeFile.open("/sys/bus/event_source/devices/intel_pt/type");
    typeFile >> attr.type;
    typeFile.close();

    // Open perf event counter
    FD = syscall(SYS_perf_event_open, &attr, TARGET_PID, -1, -1, 0);

    struct perf_event_mmap_page *header;
    void *base, *data, *aux;

    base = mmap(NULL, (1+DATA_SIZE) * PAGE_SIZE, PROT_WRITE, MAP_SHARED, FD, 0);
    if (base == MAP_FAILED)
    {
        printf("Failed to allocate BASE\n");
        exit(EXIT_FAILURE);
    }

    header = (perf_event_mmap_page *)base;
    data = (uint8_t *)base + header->data_offset;
    header->aux_offset = header->data_offset + header->data_size;
    header->aux_size = AUX_SIZE * PAGE_SIZE;
    
    aux = mmap(NULL, header->aux_size, PROT_READ, MAP_SHARED, FD, header->aux_offset);
    if (aux == MAP_FAILED)
    {
        printf("Failed to allocate AUX\n");
        exit(EXIT_FAILURE);
    }

    header->aux_head = (uint64_t)aux;
    header->aux_tail = header->aux_head + header->aux_size;

    // printf("AUX: 0x%llx-0x%llx (%llu bytes)\n", header->aux_head, header->aux_tail, header->aux_size);

    return header;
}

int main(int argc, char** argv)
{
    pthread_t listener;
    vector<struct gm_file_link> links;

    // Arg 1: target PID
    TARGET_CMD = argv[1];
    char* const command[] = {TARGET_CMD, NULL};
    TARGET_PID = fork();

    // Start target executable in child process
    if (TARGET_PID == 0)
    {
        // Pause execution of child process on exec pending decoder setup
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        // Execute target
        execve(TARGET_CMD, command, environ);
        // If this command runs something has gone terribly wrong
        exit(1);
    }
    
    printf("Target PID: %i\n", TARGET_PID);

    struct perf_event_mmap_page* header;
    int	childstatus;
    waitpid(TARGET_PID, &childstatus, 0);

    if (WIFSTOPPED(childstatus) && WSTOPSIG(childstatus) == SIGTRAP)
    {
        // Allocate memory buffer for IPT
        header = alloc_pt_buf();
        // Wait for the list of linked libraries to become fully populated
        monitor_maps(&links);
        // Tell child process to proceed
        ptrace(PTRACE_CONT, TARGET_PID);
        // Enable Intel PT recording
        syscall(SYS_ioctl, FD, PERF_EVENT_IOC_ENABLE);
    }

	struct ptxed_decoder decoder;
	struct ptxed_options options;
	struct ptxed_stats stats;
	struct pt_config config;
	struct pt_image *image;
	int errcode;

    image = NULL;

    memset(&options, 0, sizeof(options));
	memset(&stats, 0, sizeof(stats));

	errcode = ptxed_init_decoder(&decoder);
	if (errcode < 0)
    {
		report_error(errcode);
        exit(1);
	}

    pt_sb_notify_error(decoder.session, ptxed_print_error, &options);

	image = pt_image_alloc(NULL);
	if (!image)
    {
		fprintf(stderr, "%s: failed to allocate image.\n", TARGET_CMD);
        exit(1);
	}

    // options.quiet = 1;
    options.print_stats = 1;
    options.print_raw_insn = 1;

    // Load linked libraries into decoder image
    errcode = load_image(&links, &decoder, image, TARGET_CMD);
    if (errcode < 0)
    {
        report_error(errcode);
        exit(1);
    }

	pt_config_init(&config);
    config.begin = (uint8_t *)header->aux_head;
    config.end = (uint8_t *)header->aux_tail;

    alloc_decoder(&decoder, &config, image, &options, TARGET_CMD);
	if (!ptxed_have_decoder(&decoder))
    {
		fprintf(stderr, "%s: no pt.\n", TARGET_CMD);
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
        exit(1);
	}
    
    // Start decoding
	decode(&decoder, &options, &stats);

    // Clean up
    syscall(SYS_ioctl, FD, PERF_EVENT_IOC_DISABLE);
    close(FD);

	if (options.print_stats)
		print_stats(&stats);

    return 0;
}