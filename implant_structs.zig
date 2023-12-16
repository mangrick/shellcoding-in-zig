const std = @import("std");

pub const ProcessEnvironmentBlock: type = packed struct {
    InheritedAddressSpace: u8,
    ReadImageFileExecOptions: u8,
    BeingDebugged: u8,

    // Bitfield
    ImageUsesLargePages: u1,
    IsProtectedProcess: u1,
    IsImageDynamicallyRelocated: u1,
    SkipPatchingUser32Forwarders: u1,
    IsPackagedProcess: u1,
    IsAppContainer: u1,
    IsProtectedProcessLight: u1,
    IsLongPathAwareProcess: u1,

    Mutant: *anyopaque,
    ImageBaseAddress: *anyopaque,
    Ldr: *PEB_LDR_DATA,
    // ... not of interest from here ...//
};

pub const PEB_LDR_DATA: type = extern struct {
    Length: u32,
    Initialized: u32,
    SsHandle: *anyopaque,
    InLoadOrderModuleList: LIST_ENTRY,
    InMemoryOrderModuleList: LIST_ENTRY,
    InInitializationOrderModuleList: LIST_ENTRY,
    EntryInProgress: *anyopaque,
    ShutdownInProgress: u8,
    ShutdownThreadId: *anyopaque,
};

pub const LIST_ENTRY: type = extern struct {
    Flink: *LIST_ENTRY,
    Blink: *LIST_ENTRY,
};

pub const LDR_DATA_TABLE_ENTRY: type = extern struct {
    InLoadOrderLinks: LIST_ENTRY,
    InMemoryOrderLinks: LIST_ENTRY,
    InInitializationOrderLinks: LIST_ENTRY,
    DllBase: *anyopaque,
    EntryPoint: *anyopaque,
    SizeOfImage: u32,
    FullDllName: UNICODE_STRING,
    // ... not of interest from here ...//
};

pub const UNICODE_STRING: type = extern struct {
    Length: u16,
    MaximumLength: u16,
    Buffer: [*]const u16,

    pub fn format(s: UNICODE_STRING, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        _ = try writer.print("[UNICODE_STRING, Length: 0x{X}, Maximum Length: 0x{X}, Text: ", .{ s.Length, s.MaximumLength });
        var i: usize = 0;
        while (i <= s.Length / 2) : (i += 1) {
            if (s.Buffer[i] < 0x80) {
                _ = try writer.print("{c}", .{@as(u8, @truncate(s.Buffer[i]))});
            } else {
                _ = try writer.print("?", .{});
            }
        }

        try writer.writeAll("]");
    }

    pub fn equals(s: UNICODE_STRING, o: []const u8) bool {
        var i: usize = 0;
        while (i < s.Length / 2) : (i += 1) {
            if (@as(u8, @truncate(s.Buffer[i])) == o[i]) continue else return false;
        }

        if (i != o.len) return false else return true;
    }
};

pub const IMAGE_DOS_HEADER: type = extern struct { e_magic: u16, e_cblp: u16, e_cp: u16, e_crlc: u16, e_cparhdr: u16, e_minalloc: u16, e_maxalloc: u16, e_ss: u16, e_sp: u16, e_csum: u16, e_ip: u16, e_cs: u16, e_lfarlc: u16, e_ovno: u16, e_res: [4]u16, e_oemid: u16, e_oeminfo: u16, e_res2: [10]u16, e_lfanew: i32 };

pub const IMAGE_NT_HEADERS: type = extern struct {
    Signature: u32,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER,
};

pub const IMAGE_FILE_HEADER: type = extern struct {
    Machine: u16,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
};

pub const IMAGE_OPTIONAL_HEADER: type = extern struct {
    Magic: u16,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    BaseOfData: u32,
    ImageBase: u32,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u16,
    DllCharacteristics: u16,
    SizeOfStackReserve: u32,
    SizeOfStackCommit: u32,
    SizeOfHeapReserve: u32,
    SizeOfHeapCommit: u32,
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};

pub const IMAGE_DATA_DIRECTORY: type = extern struct {
    VirtualAddress: u32,
    Size: u32,
};

pub const IMAGE_EXPORT_DIRECTORY: type = extern struct {
    Characteristics: u32,
    TimeDateStamp: u32,
    MajorVersion: u16,
    MinorVersion: u16,
    Name: u32,
    Base: u32,
    NumberOfFunctions: u32,
    NumberOfNames: u32,
    AddressOfFunctions: usize,
    AddressOfNames: usize,
    AddressOfNameOrdinals: usize,
};

pub const IMAGE_DIRECTORY_ENTRY_EXPORT: i32 = 0;
