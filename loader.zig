const std = @import("std");
const windows = std.os.windows;
const kernel32 = std.os.windows.kernel32;
const coff = std.coff;

/// Not yet part of Zig's standard library
pub extern "kernel32" fn GetExitCodeThread(hProcess: windows.HANDLE, lpExitCode: *windows.DWORD) callconv(.Stdcall) windows.BOOL;

/// Parse a compiled PE-binary to extract the bytes from its code segment. Cutoff_start and cutoff_end can be used
/// to carve out the function prologue and epilogue from main to avoid call to ExitProcess.
fn extract_shellcode(allocator: std.mem.Allocator, filename: []const u8, cutoff_start: u32, cutoff_end: u32) ![]const u8 {
    const file = try std.fs.cwd().openFile(filename, .{ .mode = .read_only });
    const file_size = @as(usize, @truncate((try file.stat()).size));
    var buffer = try allocator.alloc(u8, file_size);

    // Read whole file into memory
    try file.reader().readNoEof(buffer);

    const image = try coff.Coff.init(buffer, false);
    const sections = image.getSectionHeaders();

    // Find code segment
    var code_segment_index: u32 = 0;
    for (sections, 0..) |*section, i| {
        if (section.flags.MEM_EXECUTE == 1) {
            code_segment_index = i;
            break;
        }
    }

    // Extract bytes from code segment
    const shellcode_start: u32 = sections[code_segment_index].pointer_to_raw_data;
    const shellcode_stop: u32 = shellcode_start + sections[code_segment_index].virtual_size;

    return buffer[shellcode_start + cutoff_start .. shellcode_stop - cutoff_end];
}

pub fn main() void {
    std.debug.print("[-] Parsing data from the PE-file\n", .{});
    const cutoff_start = 14; // These values need to be set manually by determining them with a disassembler / debugger
    const cutoff_end = 6;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const payload = extract_shellcode(allocator, "implant.exe", cutoff_start, cutoff_end) catch {
        std.debug.print("[-] ERROR: Could not parse compiled binary to extract the shellcode!\n", .{});
        return;
    };
    std.debug.print("[-] Shellcode extracted with a size of {d} bytes\n", .{payload.len});

    // Allocate memory for the shellcode
    var buffer = @as([*]u8, @ptrCast(kernel32.VirtualAlloc(null, payload.len, windows.MEM_COMMIT | windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)))[0..payload.len];
    std.debug.print("[-] Allocated memory at memory location {*} (payload is at {*})\n", .{ buffer, &payload });

    // Copy payload to new buffer
    std.mem.copy(u8, buffer, payload);
    std.debug.print("[-] Copied payload from the implant to newly allocated buffer\n", .{});

    // Wait for Enter
    std.debug.print("[-] Waiting for user keypress (ENTER) to start the thread\n", .{});
    var reader = std.io.getStdIn().reader();
    var buf: [5]u8 = undefined;
    _ = reader.readUntilDelimiterOrEof(&buf, '\n') catch return;

    // Start thread
    var th = kernel32.CreateThread(null, 0, @as(windows.LPTHREAD_START_ROUTINE, @ptrCast(buffer)), null, 0, null) orelse unreachable;
    var exit_code = kernel32.WaitForSingleObject(th, 0xFFFFFFFF);

    var thread_error_code: u32 = 0;
    _ = GetExitCodeThread(th, &thread_error_code);

    std.debug.print("[-] Thread terminated with exit code {d} ({d})\n", .{ thread_error_code & 0xFF, exit_code & 0xFF });
}
