#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <math.h>
#include <windows.h>
#include <omp.h>

#define THREAD_THRESHOLD 10000 

typedef struct {
    uint32_t ip;
    uint32_t timestamp;
} LogEntry;

/* =====================================================================
 * Comparators & Swaps
 * ===================================================================== */

static inline bool is_less(const LogEntry *a, const LogEntry *b) {
    return (a->ip < b->ip) || ((a->ip == b->ip) && (a->timestamp < b->timestamp));
}

static inline bool is_greater(const LogEntry *a, const LogEntry *b) {
    return (a->ip > b->ip) || ((a->ip == b->ip) && (a->timestamp > b->timestamp));
}

static inline void swap_entries(LogEntry *a, LogEntry *b) {
    LogEntry temp = *a;
    *a = *b;
    *b = temp;
}

static inline LogEntry median_of_three(LogEntry *a, LogEntry *b, LogEntry *c) {
    if (is_less(a, b)) {
        if (is_less(b, c)) return *b;
        return is_less(a, c) ? *c : *a;
    } else {
        if (is_less(a, c)) return *a;
        return is_less(b, c) ? *c : *b;
    }
}

/* =====================================================================
 * Sorting Algorithms (Introsort Implementation)
 * ===================================================================== */

void insertion_sort(LogEntry *start, LogEntry *end) {
    for (LogEntry *i = start + 1; i <= end; i++) {
        LogEntry value = *i;
        LogEntry *j = i - 1;
        while (j >= start && is_greater(j, &value)) {
            *(j + 1) = *j;
            j--;
        }
        *(j + 1) = value;
    }
}

void heapify(LogEntry *data, int size, int parent) {
    int max = parent;
    int left_child = 2 * parent + 1;
    int right_child = 2 * parent + 2;

    if (left_child < size && is_greater((data + left_child), (data + max))) {
        max = left_child;
    }
    if (right_child < size && is_greater((data + right_child), (data + max))) {
        max = right_child;
    }
    if (max != parent) {
        swap_entries(data + parent, data + max);
        heapify(data, size, max);
    }
}

void heap_sort(LogEntry *base, int size) {
    for (int i = size / 2 - 1; i >= 0; i--) {
        heapify(base, size, i);
    }
    for (int i = size - 1; i > 0; i--) {
        swap_entries(base, base + i);
        heapify(base, i, 0);
    }
}

static inline LogEntry* partition(LogEntry *start, LogEntry *end) {
    LogEntry *mid = start + (end - start) / 2;
    LogEntry pivot = median_of_three(start, mid, end);

    LogEntry *i = start - 1; 
    LogEntry *j = end + 1;

    while (1) {
        do { i++; } while (is_less(i, &pivot));
        do { j--; } while (is_greater(j, &pivot));

        if (i >= j) return j;
        swap_entries(i, j);
    }
}

void introsort_recursive(LogEntry *start, LogEntry *end, int max_depth) {
    while (end - start > 16) {
        if (max_depth == 0) {
            heap_sort(start, (int)(end - start + 1));
            return;
        }
        max_depth--;

        LogEntry *pivot_ptr = partition(start, end);

        // OpenMP tasks for large partitions
        if (end - start > THREAD_THRESHOLD) {
            #pragma omp task shared(start, pivot_ptr)
            introsort_recursive(start, pivot_ptr, max_depth);
            start = pivot_ptr + 1;
        } else {
            // Tail recursion optimization
            if (pivot_ptr - start < end - (pivot_ptr + 1)) {
                introsort_recursive(start, pivot_ptr, max_depth);
                start = pivot_ptr + 1;
            } else {
                introsort_recursive(pivot_ptr + 1, end, max_depth);
                end = pivot_ptr;
            }
        }
    }

    if (start < end) {
        insertion_sort(start, end);
    }
}

void parallel_introsort(LogEntry *array, int size) {
    if (size < 2) return;
    int max_depth = 2 * (int)log2((double)size);

    #pragma omp parallel if(size > 50000)
    {
        #pragma omp single
        introsort_recursive(array, array + size - 1, max_depth);
    }
}

/* =====================================================================
 * Fast Parsing & File I/O
 * ===================================================================== */

static inline uint32_t fast_parse_ipv4(const char **ptr) {
    uint32_t ip = 0;
    int val = 0;
    for (int i = 0; i < 4; i++) {
        val = 0;
        while (**ptr >= '0' && **ptr <= '9') {
            val = val * 10 + (**ptr - '0');
            (*ptr)++;
        }
        ip = (ip << 8) | val;
        if (**ptr == '.') (*ptr)++; 
    }
    return ip;
}

static inline uint32_t fast_parse_timestamp(const char **ptr) {
    uint32_t ts = 0;
    while (**ptr >= '0' && **ptr <= '9') {
        ts = ts * 10 + (**ptr - '0');
        (*ptr)++;
    }
    return ts;
}

/**
 * @brief Memory-maps a log file, parses IP and timestamps directly into memory,
 * and sorts the array using a multithreaded Introsort. Exposed to Python via DLL.
 */
__declspec(dllexport) LogEntry* process_logs_fast(const char *filename, int *out_total_lines) {
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        *out_total_lines = -1;
        return NULL;
    }

    DWORD file_size = GetFileSize(hFile, NULL);
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    const char *memory_mapped_file = (const char *)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

    // Conservative memory allocation estimation (avg 15 bytes per line)
    int max_lines = file_size / 15; 
    LogEntry *logs = (LogEntry *)malloc(max_lines * sizeof(LogEntry));
    if (!logs) {
        UnmapViewOfFile(memory_mapped_file);
        CloseHandle(hMap);
        CloseHandle(hFile);
        *out_total_lines = -1;
        return NULL;
    }

    int count = 0;
    const char *ptr = memory_mapped_file;
    const char *end = memory_mapped_file + file_size;

    // Zero-copy parsing
    while (ptr < end) {
        while (ptr < end && (*ptr == ' ' || *ptr == '\n' || *ptr == '\r')) ptr++;
        if (ptr >= end) break;

        logs[count].ip = fast_parse_ipv4(&ptr);
        while (ptr < end && *ptr == ' ') ptr++; 
        logs[count].timestamp = fast_parse_timestamp(&ptr);
        count++;

        while (ptr < end && *ptr != '\n') ptr++;
    }

    // Windows resource cleanup
    UnmapViewOfFile(memory_mapped_file);
    CloseHandle(hMap);
    CloseHandle(hFile);

    *out_total_lines = count;

    if (count > 0) {
        parallel_introsort(logs, count);
    }

    return logs;
}

__declspec(dllexport) void free_log_memory(LogEntry *ptr) {
    if (ptr) {
        free(ptr);
    }
}