const std = @import("std");
const api = @import("implant_structs.zig");
const obf = @import("obfuscation.zig");
const sos = @import("stack_allocator.zig").StringsOnStackAllocator;

/// Win32 API function pointer types
const LoadLibraryA: type = *const fn ([*]const u8) callconv(.Stdcall) *api.IMAGE_DOS_HEADER;
const MessageBoxA: type = *const fn (i32, [*]const u8, [*]const u8, u32) callconv(.Stdcall) i32;

/// Error types that the shellcode can encounter
const ImplantError = error{ ModuleNotFound, FunctionNotFound, OutOfMemory };

/// Struct representing a function (name + function pointer)
fn Function(comptime T: type) type {
    return struct { Name: []const u8, call: T };
}

/// Data fields that the implant will need to spawn a message box
const ImplantData: type = struct {
    LoadLibraryA: Function(LoadLibraryA),
    MessageBoxA: Function(MessageBoxA),

    Message: []const u8,
    Caption: []const u8,

    Kernel32_dll: []const u8,
    User32_dll: []const u8,
};

/// Find the memory address of the next instruction after returning
/// from this function. Noinline is strictly necessary here to prevent
/// the compiler from optimizing the assembly call as an inline directive.
/// We rely here on the call instruction to get the next EIP location
/// from the stack pointer
noinline fn get_eip() *usize {
    return asm volatile ("mov (%esp), %eax"
        : [ret] "={eax}" (-> *usize),
    );
}

/// Place a static zero-terminated string somewhere in the code segment and return an
/// array pointing to the memory in the code segment that contains the string.
noinline fn place_string_in_cs(comptime s: []const u8) *[s.len]u8 {
    // Get location of the instruction pointer
    var eax: *usize = get_eip();

    // Add 6 to string length to account for number of bytes from the mnemonics (5) and
    // the zero-terminator
    // TODO: Determine the number of bytes for the mnemonic (5) from the length of the string.
    asm volatile (std.fmt.comptimePrint("add ${d}, %eax", .{s.len + 6}));

    // Jump over character bytes of the target string
    asm volatile ("jmp *%eax");

    // Insert string into the code segment
    asm volatile (std.fmt.comptimePrint(".asciz \"{s}\"", .{s}));

    // Subtract the amount of bytes of the string to get the pointer of the first character
    asm volatile (std.fmt.comptimePrint("sub ${d}, %eax", .{s.len + 1}));

    // Reinterpret data in code segment into a slice
    return @as([*]u8, @ptrCast(eax))[0..s.len];
}

/// Return the address of the ProcessEnvironmentBlock
/// On x86, this struct is located in the FS register at 0x30
inline fn get_PEB() *api.ProcessEnvironmentBlock {
    return asm volatile ("mov %fs:0x30, %eax"
        : [ret] "={eax}" (-> *api.ProcessEnvironmentBlock),
    );
}

/// Return the address of a loaded module in the InMemoryModuleList
fn get_module(dll_name: []const u8) ImplantError!*api.IMAGE_DOS_HEADER {
    const peb: *api.ProcessEnvironmentBlock = get_PEB();
    var entry: *align(4) api.LIST_ENTRY = &peb.Ldr.InMemoryOrderModuleList;
    var module: *api.LDR_DATA_TABLE_ENTRY = @ptrCast(entry.Flink);

    while (!module.FullDllName.equals(dll_name)) {
        entry = &module.InLoadOrderLinks;
        module = @ptrCast(entry.Flink);

        // Check if we returned back to the head. In this case the module could not be found.
        if (entry == &peb.Ldr.InMemoryOrderModuleList) {
            return ImplantError.ModuleNotFound;
        }
    }

    // The address of the loaded module is stored in the first pointer of the InInitializationOrderLinks field.
    return @ptrCast(module.InInitializationOrderLinks.Flink);
}

/// Return the length of a zero-terminated c-string
fn get_string_length(p: [*:0]const u8) usize {
    var i: usize = 0;
    while (p[i] != 0) {
        i += 1;
    }
    return i;
}

/// Load manually the function pointer from the EXPORT_ADDRESS_TABLE
fn get_win32_function(pe_module: *api.IMAGE_DOS_HEADER, func_name: []const u8) ImplantError!*usize {
    // Cast pointer to PE module with an alignment of 1 to allow pointer arithmetic per byte
    const imagebase: [*]u8 = @ptrCast(pe_module);

    // Traverse the PE file format to find the optional header
    const nt_headers: *api.IMAGE_NT_HEADERS = @alignCast(@ptrCast(imagebase + @as(usize, @bitCast(pe_module.e_lfanew))));
    const nt_optional: *api.IMAGE_OPTIONAL_HEADER = &nt_headers.OptionalHeader;

    // Go to the export directory and its section
    const export_directory: *api.IMAGE_DATA_DIRECTORY = &nt_optional.DataDirectory[api.IMAGE_DIRECTORY_ENTRY_EXPORT];
    const export_section: *api.IMAGE_EXPORT_DIRECTORY = @alignCast(@ptrCast(imagebase + @as(usize, @bitCast(export_directory.VirtualAddress))));

    // Iterate over each Function name and compare it with the target
    const names: [*]usize = @alignCast(@ptrCast(imagebase + export_section.AddressOfNames));

    var found_at: ?usize = null;
    for (0..export_section.NumberOfNames) |n| {
        const exported_func_name: [*:0]const u8 = @alignCast(@ptrCast(imagebase + names[n]));
        const exported_name_length = get_string_length(exported_func_name);

        // Compare exported function name with target function name
        if (std.mem.eql(u8, func_name, exported_func_name[0..exported_name_length])) {
            found_at = n;
            break;
        }
    }

    if (found_at == null) {
        return ImplantError.FunctionNotFound;
    }

    // Lookup ordinal value of function
    const ordinals: [*]u16 = @alignCast(@ptrCast(imagebase + export_section.AddressOfNameOrdinals));
    const ordinal_idx: u16 = ordinals[found_at.?];

    // Lookup function address at ordinal index
    const function_pointers: [*]usize = @alignCast(@ptrCast(imagebase + export_section.AddressOfFunctions));
    const function_pointer: usize = function_pointers[ordinal_idx];
    const function_pointer_va = @as(*usize, @alignCast(@ptrCast(imagebase + function_pointer)));

    return function_pointer_va;
}

fn implant_main() ImplantError!u8 {
    var data: ImplantData = undefined;
    const caeser_shift = 3;

    // Store function names and displayed strings used by the implant in the code segment
    data.LoadLibraryA.Name = place_string_in_cs(obf.caeser_encrypt("LoadLibraryA", caeser_shift));
    data.MessageBoxA.Name = place_string_in_cs("MessageBoxA");
    data.Message = place_string_in_cs("Hello World!\n");
    data.Caption = place_string_in_cs("Merry Christmas\n");

    // Store User32.dll and Kernel32.Dll on the stack
    var dll_names: [32]u8 = undefined;
    var allocator = sos.init(&dll_names);
    data.User32_dll = allocator.alloc("User32.dll");
    data.Kernel32_dll = allocator.alloc("KERNEL32.DLL");
    defer allocator.free(data.User32_dll);
    defer allocator.free(data.Kernel32_dll);

    // Get Kernel32 module for LoadLibraryA function export
    const kernel32: *api.IMAGE_DOS_HEADER = try get_module(data.Kernel32_dll);

    // Decrypt the name for LoadLibraryA
    var load_library_a_decrypted: [12]u8 = undefined;
    obf.caesar_decrypt(data.LoadLibraryA.Name, caeser_shift, &load_library_a_decrypted);

    // Retrieve the function pointers for LoadLibraryA from Kernel32
    data.LoadLibraryA.call = @ptrCast(try get_win32_function(kernel32, &load_library_a_decrypted));

    // Load User32.dll
    const handle: *api.IMAGE_DOS_HEADER = data.LoadLibraryA.call(data.User32_dll.ptr);

    // Load MessageBoxA function pointer
    data.MessageBoxA.call = @ptrCast(try get_win32_function(handle, data.MessageBoxA.Name));

    // Make the call to MessageBoxA
    _ = data.MessageBoxA.call(0, data.Message.ptr, data.Caption.ptr, 0);
    return 0;
}

pub fn main() u8 {
    // Calling the main shellcode (return error with try during debugging)
    return implant_main() catch 1;
}
