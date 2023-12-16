const std = @import("std");
const ImplantError = @import("implant.zig").ImplantError;

/// Determine the size of the buffer containing all the push instructions for the inline assembly call
inline fn get_return_buffer_size(comptime len: usize) usize {
    return @ceil(@as(f32, (len + 1)) / 4) * 17;
}

/// Copies the data from the src buffer into the dest buffer with the prefixed push instruction term
inline fn insert_into_buffer(src: []u8, dest: []u8, start: usize) void {
    _ = std.fmt.bufPrint(dest[start .. start + src.len + 13], "push $0x{}\n", .{std.fmt.fmtSliceHexLower(src)}) catch unreachable;
}

/// Generate the sequence of push instructions to based on the provided string
inline fn push_instructions(comptime s: []const u8) *const [get_return_buffer_size(s.len)]u8 {
    comptime {
        var return_buffer: [get_return_buffer_size(s.len)]u8 = undefined;
        var return_buffer_pos = 0;

        var stack_buffer: [4]u8 = std.mem.zeroes([4]u8);

        var i: usize = s.len;
        var c: usize = 1;
        while (i > 0) {
            i -= 1;

            stack_buffer[c] = s[i];
            c += 1;

            if (c == 4) {
                insert_into_buffer(&stack_buffer, &return_buffer, return_buffer_pos);
                return_buffer_pos += 17;
                @memset(&stack_buffer, 0);
                c = 0;
            }
        }
        if (c > 0) {
            insert_into_buffer(&stack_buffer, &return_buffer, return_buffer_pos);
        }

        return &return_buffer;
    }
}

pub const StringsOnStackAllocator = struct {
    end_index: usize,
    buffer: []u8,

    fn as_slice(buffer: []u8, offset: usize, len: usize) []const u8 {
        return @as([*]u8, @ptrCast(buffer))[offset .. offset + len];
    }

    pub fn init(buffer: []u8) StringsOnStackAllocator {
        return StringsOnStackAllocator{
            .buffer = buffer,
            .end_index = 0,
        };
    }

    pub noinline fn alloc(self: *StringsOnStackAllocator, comptime s: []const u8) []const u8 {
        // Determine the number of bytes necessary on the stack
        const nb_bytes_on_stack = @as(usize, @ceil(@as(f32, (s.len + 1)) / @sizeOf(usize)) * @sizeOf(usize));
        // if (self.end_index + nb_bytes_on_stack > self.buffer.len) return ImplantError.OutOfMemory;

        // Compute the offset where the resuting string will be located (relative to the buffer address)
        // Minus 1 due to buffer being 0-indexed
        const offset = self.end_index + nb_bytes_on_stack - s.len - 1;

        // Insert location will be the next multiple of 4 (native register size) added to buffer location and end_index
        const insert_location = self.buffer.ptr + nb_bytes_on_stack + self.end_index;

        // Save current stack pointer (in the EAX register)
        var stack_pointer = asm volatile ("mov %esp, %eax"
            : [ret] "={eax}" (-> *usize),
        );

        // Put stack pointer to the location where the data of buffer is stored on the stack
        // (with an offset by end_index)
        asm volatile ("mov %[input], %esp"
            : // Nothing to return
            : [input] "number" (insert_location),
        );

        // Push string into the buffer on the stack
        const inst: []const u8 = push_instructions(s);
        asm volatile (inst);

        // Restore the stack pointer
        asm volatile ("mov %eax, %esp"
            : // Nothing to return
            : [number] "{eax}" (stack_pointer),
        );

        // Increase buffer end by the amount of used bytes
        self.end_index += nb_bytes_on_stack;
        return as_slice(self.buffer, offset, s.len);
    }

    pub noinline fn free(self: *StringsOnStackAllocator, s: []const u8) void {
        self.end_index -= (s.len + 1 + @sizeOf(usize) - 1) & ~@as(usize, (@sizeOf(usize) - 1));
    }
};
